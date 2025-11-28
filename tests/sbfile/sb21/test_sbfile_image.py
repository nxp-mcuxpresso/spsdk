#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2.x image file testing module.

This module contains comprehensive tests for SB2.0 and SB2.1 secure boot file
image creation, parsing, and validation functionality. It verifies the correct
behavior of SB file builders, parsers, and various validation scenarios including
both positive and negative test cases for error handling.
"""

import os
from binascii import unhexlify
from datetime import datetime, timezone
from typing import Union

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.exceptions import SPSDKError
from spsdk.image.otfad.otfad import KeyBlob, Otfad
from spsdk.mboot.memories import MemIdEnum
from spsdk.sbfile.sb2.commands import (
    CmdCall,
    CmdErase,
    CmdJump,
    CmdKeyStoreBackup,
    CmdKeyStoreRestore,
    CmdLoad,
    CmdReset,
    CmdVersionCheck,
    VersionCheckType,
)
from spsdk.sbfile.sb2.images import (
    BootImageV20,
    BootImageV21,
    BootSectionV2,
    CertBlockV1,
    SBV2xAdvancedParams,
)
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align_block
from spsdk.utils.spsdk_enum import SpsdkEnum

kek_value = unhexlify("AC701E99BD3492E419B756EADC0985B3D3D0BC0FDB6B057AA88252204C2DA732")


class SectionsContent(SpsdkEnum):
    """Test enumeration for SB2.1 file sections content types.

    This enumeration defines different types of section content configurations
    used for testing SB2.1 file image generation and validation scenarios.
    """

    SIMPLE = (1, "simple", "one simple section")
    ADVANCED = (2, "advanced", "one simple section and second bigger section")
    NEW_CMDS = (3, "newcommands", "one section with new commands")


def test_sb20_parser(data_dir: str) -> None:
    """Test SB2.0 file parser functionality.

    Verifies that the BootImageV20.parse method can successfully parse a valid
    SB2.0 file and return a proper BootImageV20 instance. Also validates that
    the string representation method works correctly.

    :param data_dir: Directory path containing test data files including the SB2.0_Not_Signed.sb2 file
    """
    with open(os.path.join(data_dir, "SB2.0_Not_Signed.sb2"), "rb") as file:
        img_obj = BootImageV20.parse(file.read(), kek=kek_value)

    assert isinstance(img_obj, BootImageV20)

    # check __str__() produces something
    assert str(img_obj)


def gen_cert_block(data_dir: str, sign_bits: int) -> CertBlockV1:
    """Generate certificate block for SB2.x files.

    This function creates a certificate block by loading a certificate file
    based on the signature key length and configuring it for the Ambassador
    family revision.

    :param data_dir: Absolute path to directory containing certificate files.
    :param sign_bits: Signature key length in bits used to select certificate file.
    :raises SPSDKError: If certificate file cannot be loaded or processed.
    :return: Configured certificate block for SB2.x files.
    """
    cert_obj = Certificate.load(
        os.path.join(data_dir, "selfsign_" + str(sign_bits) + "_v3.der.crt")
    )
    root_key_hash = cert_obj.public_key_hash()

    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cb.set_root_key_hash(0, root_key_hash)
    cb.add_certificate(cert_obj)
    return cb


def get_boot_sections(
    data_dir: str, otfad: bool, sect_cont: SectionsContent, load_addr: int
) -> list[BootSectionV2]:
    """Create list of boot sections for SB 2.x file.

    This function generates boot sections for testing purposes, including support for OTFAD encryption
    and different section content types. It loads a boot image from the specified directory and
    creates appropriate boot sections with various commands based on the configuration.

    :param data_dir: Absolute path to directory containing boot image file
    :param otfad: True to encrypt section with OTFAD; False otherwise
    :param sect_cont: Type of sections content to generate for testing
    :param load_addr: Address where to load the image (for simple section)
    :return: List of boot sections configured according to the specified parameters
    """
    result = list()

    class TestExtMemId(MemIdEnum):
        """Test enumeration for external memory identifiers.

        This class extends MemIdEnum to provide test-specific memory identifiers
        used in SBFile testing scenarios for validating external memory operations.

        :cvar TEST: Test memory identifier for validation purposes.
        """

        TEST = (3, "TEST", "Test memory id")

    # load input image (binary)
    with open(os.path.join(data_dir, "boot_image.bin"), "rb") as f:
        plain_image = f.read()

    # OTFAD
    key_blobs_data: list[bytes] = []
    if otfad:
        key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
        otfad_obj = Otfad(family=FamilyRevision("mimxrt595s"), kek=key)
        # key blob 0
        key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
        counter = bytes.fromhex("5689fab8b4bfb264")
        key_blob = KeyBlob(
            0x08001000, 0x0800F3FF, key, counter, zero_fill=bytes(4), crc=bytes(4)
        )  # zero_fill and crc should be used only for testing !
        otfad_obj[0] = key_blob
        key_blobs_data = []
        key_blobs_data.append(
            key_blob.export(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))
        )
        # verify `otfad.encrypt_key_blobs` returns the same
        assert (
            key_blobs_data[0]
            == otfad_obj.encrypt_key_blobs(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))[
                :64
            ]
        )
        # key blob 1
        if sect_cont == SectionsContent.ADVANCED:
            key = bytes.fromhex("12345678901234567890123456789012")
            counter = bytes.fromhex("0011223344556677")
            key_blob1 = KeyBlob(
                0x08010000, 0x0801F3FF, key, counter, zero_fill=bytes(4), crc=bytes(4)
            )  # zero_fill and crc should be used only for testing !
            otfad_obj.add_key_blob(key_blob1)
            key_blobs_data.append(
                key_blob1.export(kek=bytes.fromhex("0123456789ABCDEF0123456789ABCDEF"))
            )
        # encrypted image
        encr_image = otfad_obj.encrypt_image(align_block(plain_image, 512), load_addr, True)
    else:
        encr_image = plain_image

    if sect_cont == SectionsContent.ADVANCED:
        # add boot sections 1 - advanced
        boot_section2 = BootSectionV2(
            1,
            CmdErase(address=0, length=0x2800),
            CmdLoad(address=0x10000000, data=plain_image),
            CmdLoad(address=0x20000000, data=plain_image),
            CmdCall(0xFFFF0000),
            CmdJump(0x12345678),
            CmdReset(),
            hmac_count=5,
        )
        assert boot_section2.uid == 1
        result.append(boot_section2)

    # create boot section 0
    if sect_cont == SectionsContent.NEW_CMDS:
        boot_section0 = BootSectionV2(
            0,
            CmdVersionCheck(VersionCheckType.SECURE_VERSION, 0x16),
            CmdVersionCheck(VersionCheckType.NON_SECURE_VERSION, 15263),
            CmdErase(address=0, length=0x2800),
            CmdLoad(address=load_addr, data=encr_image),
            CmdKeyStoreBackup(0x12345678, TestExtMemId.TEST),  # type: ignore
            CmdKeyStoreRestore(0x12345678, TestExtMemId.TEST),  # type: ignore
            hmac_count=1,
        )
    else:
        boot_section0 = BootSectionV2(
            0,
            CmdErase(address=0, length=0x2800),
            CmdLoad(address=load_addr, data=encr_image),
            hmac_count=10,
        )
    for index, key_blob_data in enumerate(key_blobs_data):
        key_blob_aligned = align_block(
            key_blob_data, 256
        )  # it seems key-blob from elf-to-sb is aligned to 256
        boot_section0.append(CmdLoad(address=0x8000000 + 0x100 * index, data=key_blob_aligned))
    boot_section0.append(CmdReset())
    result.append(boot_section0)

    return result


@pytest.mark.parametrize(
    "sb_minor_ver,sign_bits,otfad,sect_cont,load_addr",
    [
        (0, 0, False, SectionsContent.SIMPLE, 0x0),  # SB2.0 unsigned simple
        (0, 2048, False, SectionsContent.ADVANCED, 0x80000000),  # SB2.0 signed advanced
        (
            0,
            4096,
            False,
            SectionsContent.SIMPLE,
            0x80000000,
        ),  # SB2.0 signed simple, 4096 key length
        (0, 2048, True, SectionsContent.SIMPLE, 0x8001000),  # SB2.0 OTFAD simple
        (
            1,
            2048,
            False,
            SectionsContent.SIMPLE,
            0x80000000,
        ),  # SB2.1 signed simple, 2048 key length
        (
            1,
            4096,
            False,
            SectionsContent.SIMPLE,
            0x80000000,
        ),  # SB2.1 signed simple, 4096 key length
        (1, 2048, False, SectionsContent.ADVANCED, 0x80000000),  # SB2.1 signed advanced
        (1, 2048, True, SectionsContent.SIMPLE, 0x8001000),  # SB2.1 OTFAD simple
        (1, 2048, True, SectionsContent.ADVANCED, 0x8001000),  # SB2.1 OTFAD advanced
        (1, 2048, False, SectionsContent.NEW_CMDS, 0x0000000),  # SB2.1 new commands
    ],
)
def test_sb2x_builder(
    data_dir: str,
    sb_minor_ver: int,
    sign_bits: int,
    otfad: bool,
    sect_cont: SectionsContent,
    load_addr: int,
) -> None:
    """Test SB2.x builder in several use-cases.

    Creates and validates SB2.0/SB2.1 boot images with different configurations including
    signed/unsigned variants, OTFAD support, and various section contents. The test
    compares generated output against expected reference files.

    :param data_dir: Absolute path to directory containing test data files.
    :param sb_minor_ver: SB version selector (0 for SB2.0, 1 for SB2.1).
    :param sign_bits: Signature size in bits (0 for unsigned, 2048 or 4096 for signed).
    :param otfad: Enable OTFAD (On-The-Fly AES Decryption) support.
    :param sect_cont: Content configuration for boot sections to test.
    :param load_addr: Load address for simple section content.
    """
    assert sb_minor_ver in [0, 1]
    assert sign_bits in [0, 2048, 4096]
    signed = sign_bits != 0
    if (sb_minor_ver == 1) or otfad:
        assert signed

    # this is hardcoded in the test; if not specified, random values will be used
    dek_value = b"\xa0" * 32
    mac_value = b"\x0b" * 32

    # this is hardcoded in the test; if not specified, current value will be used
    timestamp = datetime.fromtimestamp(
        int(datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc).timestamp())
    )
    adv_params = SBV2xAdvancedParams(
        dek=dek_value, mac=mac_value, nonce=bytes(16), timestamp=timestamp
    )

    # create boot image
    boot_image: Union[BootImageV20, BootImageV21]
    if sb_minor_ver == 0:
        boot_image = BootImageV20(
            signed,
            kek=kek_value,
            product_version="1.0.0",
            component_version="1.0.0",
            build_number=1,
            # parameters fixed for test only, do not use in production
            advanced_params=adv_params,
        )
    else:
        boot_image = BootImageV21(
            kek=kek_value,
            product_version="1.0.0",
            component_version="1.0.0",
            build_number=1,
            # parameters fixed for test only, do not use in production
            advanced_params=adv_params,
            flags=0x0008,
        )

    if signed:
        boot_image.cert_block = gen_cert_block(data_dir, sign_bits)
        private_key = os.path.join(data_dir, "selfsign_privatekey_rsa" + str(sign_bits) + ".pem")
        signature_provider = PlainFileSP(private_key)

        boot_image.signature_provider = signature_provider

    for sect in get_boot_sections(data_dir, otfad, sect_cont, load_addr):
        boot_image.add_boot_section(sect)

    result = boot_image.export(
        padding=bytes(8)
    )  # padding is added for tests only, do not use for production:

    # test raw_size
    assert len(result) == boot_image.raw_size

    # check that __str__() prints anything
    assert str(boot_image)

    sect_cont_str = sect_cont.label
    if otfad:
        mode = "otfad"
    elif signed:
        mode = "signed" + str(sign_bits)
    else:
        mode = "unsigned"
    expected_file_name = f"expected_sb2_{str(sb_minor_ver)}_{sect_cont_str}_{mode}.sb2"

    with open(os.path.join(data_dir, expected_file_name), "rb") as f:
        expected = f.read()

    if result != expected:  # if result does not match, save it for debugging
        with open(
            os.path.join(data_dir, expected_file_name.replace("expected_", "generated_")),
            "wb",
        ) as f:
            f.write(result)

    assert result == expected


def test_sb2_0_builder_validation(data_dir: str) -> None:
    """Test SB2.0 builder validation for required fields.

    Validates that the SB2.0 builder raises appropriate exceptions when required
    fields are missing during the boot image creation process. Tests scenarios
    including missing boot section, missing certificate block, and missing private key.

    :param data_dir: Directory path containing test data files for boot sections and certificates.
    :raises SPSDKError: When required fields are not defined in the boot image builder.
    """
    # create boot image
    boot_image = BootImageV20(
        True, kek=kek_value, product_version="1.0.0", component_version="1.0.0", build_number=1
    )

    # missing boot section
    with pytest.raises(SPSDKError):
        boot_image.export()

    for boot_sect in get_boot_sections(data_dir, False, SectionsContent.SIMPLE, 0):
        boot_image.add_boot_section(boot_sect)

    # missing certificate block
    with pytest.raises(SPSDKError):
        boot_image.export()

    boot_image.cert_block = gen_cert_block(data_dir, 2048)
    # missing private key
    with pytest.raises(SPSDKError):
        boot_image.export()


def test_sb2_1_builder_validation(data_dir: str) -> None:
    """Test SB2.1 builder validation for required fields.

    Validates that SPSDKError exceptions are properly raised when attempting to export
    a BootImageV21 instance with missing required components: boot section, certificate
    block, and private key.

    :param data_dir: Directory path containing test data files for boot sections and certificates.
    :raises SPSDKError: When required fields are missing during export validation.
    """
    # create boot image
    boot_image = BootImageV21(
        kek=kek_value,
        product_version="1.0.0",
        component_version="1.0.0",
        build_number=1,
        flags=0x0008,
    )

    # missing boot section
    with pytest.raises(SPSDKError):
        boot_image.export()

    for boot_sect in get_boot_sections(data_dir, False, SectionsContent.SIMPLE, 0):
        boot_image.add_boot_section(boot_sect)

    # missing certificate
    with pytest.raises(SPSDKError):
        boot_image.export()

    boot_image.cert_block = gen_cert_block(data_dir, 2048)
    # missing private key
    with pytest.raises(SPSDKError):
        boot_image.export()


def test_invalid_boot_section_v21() -> None:
    """Test that adding an invalid boot section raises SPSDKError.

    Verifies that the BootImageV21 class properly validates boot section
    parameters and raises an appropriate exception when an invalid section
    type is provided.

    :raises SPSDKError: When an invalid boot section is added to the boot image.
    """
    boot_img = BootImageV21(kek=kek_value)
    with pytest.raises(SPSDKError):
        boot_img.add_boot_section(section=5)  # type: ignore


def test_invalid_boot_section_v2() -> None:
    """Test that adding an invalid boot section to BootImageV20 raises SPSDKError.

    This test verifies that the add_boot_section method properly validates
    section parameters and raises an appropriate exception when an invalid
    section value is provided.

    :raises SPSDKError: When an invalid section parameter is passed to add_boot_section.
    """
    boot_img = BootImageV20(kek=kek_value, signed=False)
    with pytest.raises(SPSDKError):
        boot_img.add_boot_section(section=5)  # type: ignore


def test_invalid_advanced_params() -> None:
    """Test invalid advanced parameters for SBV2xAdvancedParams.

    This test verifies that SBV2xAdvancedParams properly validates input parameters
    and raises appropriate exceptions when invalid data is provided. It tests both
    invalid DEK/MAC lengths and invalid nonce length scenarios.

    :raises SPSDKError: When DEK or MAC have invalid length (33 bytes instead of expected length).
    :raises SPSDKError: When nonce has invalid length (33 bytes instead of expected length).
    """
    with pytest.raises(SPSDKError, match="Invalid dek or mac"):
        SBV2xAdvancedParams(dek=bytes(33), mac=bytes(33))
    with pytest.raises(SPSDKError, match="Invalid length of nonce"):
        SBV2xAdvancedParams(nonce=bytes(33))


def test_invalid_boot_image_v2() -> None:
    """Test invalid boot image v2 configurations and error handling.

    Validates that BootImageV20 properly raises SPSDKError exceptions for various
    invalid configurations including invalid DEK/MAC parameters, improper certificate
    block usage, and missing certification blocks.

    :raises SPSDKError: When DEK or MAC parameters are invalid.
    :raises SPSDKError: When certificate block is used with unsigned SB file.
    :raises SPSDKError: When certification block is not present for size calculations.
    """
    with pytest.raises(SPSDKError, match="Invalid dek or mac"):
        BootImageV20(
            True, kek=kek_value, advanced_params=SBV2xAdvancedParams(dek=bytes(33), mac=bytes(33))
        )
    bimg = BootImageV20(False, kek=kek_value)

    with pytest.raises(
        SPSDKError, match="Certificate block cannot be used unless SB file is signed"
    ):
        bimg.cert_block = CertBlockV1(FamilyRevision("Ambassador"))
    bimg = BootImageV20(True, kek=bytes(31))
    bimg.cert_block = None
    with pytest.raises(SPSDKError, match="Certification block not present"):
        bimg.raw_size_without_signature

    bimg = BootImageV20(True, kek=bytes(31))
    with pytest.raises(SPSDKError, match="Certification block not present"):
        bimg.raw_size


def test_invalid_boot_image_v2_invalid_export() -> None:
    """Test invalid boot image v2 export with invalid DEK.

    This test verifies that exporting a BootImageV20 with an empty DEK
    raises the appropriate SPSDKError with the expected error message.

    :raises SPSDKError: When DEK or MAC is invalid during export.
    """
    bimg = BootImageV20(True, kek=bytes(31))
    bimg._dek = bytes()
    with pytest.raises(SPSDKError, match="Invalid dek or mac"):
        bimg.export()
