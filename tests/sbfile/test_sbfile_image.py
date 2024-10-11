#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from binascii import unhexlify
from datetime import datetime, timezone

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import get_signature_provider
from spsdk.exceptions import SPSDKError
from spsdk.mboot.memories import ExtMemId, MemIdEnum
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
from spsdk.utils.crypto.otfad import KeyBlob, Otfad
from spsdk.utils.misc import align_block
from spsdk.utils.spsdk_enum import SpsdkEnum

kek_value = unhexlify("AC701E99BD3492E419B756EADC0985B3D3D0BC0FDB6B057AA88252204C2DA732")


class SectionsContent(SpsdkEnum):
    """type of sections content to test"""

    SIMPLE = (1, "simple", "one simple section")
    ADVANCED = (2, "advanced", "one simple section and second bigger section")
    NEW_CMDS = (3, "newcommands", "one section with new commands")


def test_sb20_parser(data_dir):
    """Test parser"""
    with open(os.path.join(data_dir, "SB2.0_Not_Signed.sb2"), "rb") as file:
        img_obj = BootImageV20.parse(file.read(), kek=kek_value)

    assert isinstance(img_obj, BootImageV20)

    # check __str__() produces something
    assert str(img_obj)


def gen_cert_block(data_dir, sign_bits) -> CertBlockV1:
    """Shared function to generate certificate block for SB2.x
    :param data_dir: absolute path to load certificate
    :param sign_bits: signature key length in bits

    :return: certificate block for SB2.x
    """
    cert_obj = Certificate.load(
        os.path.join(data_dir, "sb2_x", "selfsign_" + str(sign_bits) + "_v3.der.crt")
    )
    root_key_hash = cert_obj.public_key_hash()

    cb = CertBlockV1()
    cb.set_root_key_hash(0, root_key_hash)
    cb.add_certificate(cert_obj)
    return cb


def get_boot_sections(
    data_dir: str, otfad: bool, sect_cont: SectionsContent, load_addr: int
) -> list[BootSectionV2]:
    """Create list of boot sections for SB 2.x file

    :param data_dir: absolute path to load boot image
    :param otfad: True to encrypt section with OTFAD; False otherwise
    :param sect_cont: sections content to test
    :param load_addr: address where to load the image (for simple section)
    :return:
    """
    result = list()

    class TestExtMemId(MemIdEnum):
        """McuBoot External Memory Property Tags."""

        TEST = (3, "TEST", "Test memory id")

    # load input image (binary)
    with open(os.path.join(data_dir, "sb2_x", "boot_image.bin"), "rb") as f:
        plain_image = f.read()

    # OTFAD
    key_blobs_data = list()
    if otfad:
        otfad = Otfad()
        # key blob 0
        key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
        counter = bytes.fromhex("5689fab8b4bfb264")
        key_blob = KeyBlob(
            0x08001000, 0x0800F3FF, key, counter, zero_fill=bytes(4), crc=bytes(4)
        )  # zero_fill and crc should be used only for testing !
        otfad.add_key_blob(key_blob)
        key_blobs_data = list()
        key_blobs_data.append(
            key_blob.export(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))
        )
        # verify `otfad.encrypt_key_blobs` returns the same
        assert (
            key_blobs_data[0]
            == otfad.encrypt_key_blobs(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))[:64]
        )
        # key blob 1
        if sect_cont == SectionsContent.ADVANCED:
            key = bytes.fromhex("12345678901234567890123456789012")
            counter = bytes.fromhex("0011223344556677")
            key_blob1 = KeyBlob(
                0x08010000, 0x0801F3FF, key, counter, zero_fill=bytes(4), crc=bytes(4)
            )  # zero_fill and crc should be used only for testing !
            otfad.add_key_blob(key_blob1)
            key_blobs_data.append(
                key_blob1.export(kek=bytes.fromhex("0123456789ABCDEF0123456789ABCDEF"))
            )
        # encrypted image
        encr_image = otfad.encrypt_image(align_block(plain_image, 512), load_addr, True)
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
            CmdKeyStoreBackup(0x12345678, TestExtMemId.TEST),
            CmdKeyStoreRestore(0x12345678, TestExtMemId.TEST),
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
):
    """Test SB2.x builder in several use-cases

    :param data_dir: absolute path to load data
    :param sb_minor_ver: 0 or 1 to select SB2.0 or SB2.1
    :param sign_bits: size of the signature in bits: 0 for unsigned; 2048 or 4096
    :param sect_cont: content of the sections to test
    :param load_addr: load address for simple section
    """
    assert sb_minor_ver in [0, 1]
    assert sign_bits in [0, 2048, 4096]
    signed = sign_bits != 0
    if (sb_minor_ver == 1) or otfad:
        assert signed

    # this is hardcoded in the test; if not specified, random values will be used
    dek_value = b"\xA0" * 32
    mac_value = b"\x0B" * 32

    # this is hardcoded in the test; if not specified, current value will be used
    timestamp = datetime.fromtimestamp(
        int(datetime(2020, month=1, day=31, hour=0, tzinfo=timezone.utc).timestamp())
    )
    adv_params = SBV2xAdvancedParams(
        dek=dek_value, mac=mac_value, nonce=bytes(16), timestamp=timestamp
    )

    # create boot image
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
        private_key = os.path.join(
            data_dir, "sb2_x", "selfsign_privatekey_rsa" + str(sign_bits) + ".pem"
        )
        signature_provider = get_signature_provider(local_file_key=private_key)

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

    with open(os.path.join(data_dir, "sb2_x", expected_file_name), "rb") as f:
        expected = f.read()

    if result != expected:  # if result does not match, save it for debugging
        with open(
            os.path.join(data_dir, "sb2_x", expected_file_name.replace("expected_", "generated_")),
            "wb",
        ) as f:
            f.write(result)

    assert result == expected


def test_sb2_0_builder_validation(data_dir):
    """Validate exception from SB2.0 builder, if any required fields are not defined"""
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


def test_sb2_1_builder_validation(data_dir):
    """Validate exception from from SB2.1 builder, if any required fields are not defined"""
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


def test_invalid_boot_section_v21():
    boot_img = BootImageV21(kek=kek_value)
    with pytest.raises(SPSDKError):
        boot_img.add_boot_section(section=5)


def test_invalid_boot_section_v2():
    boot_img = BootImageV20(kek=kek_value, signed=False)
    with pytest.raises(SPSDKError):
        boot_img.add_boot_section(section=5)


def test_invalid_advanced_params():
    with pytest.raises(SPSDKError, match="Invalid dek or mac"):
        SBV2xAdvancedParams(dek=bytes(33), mac=bytes(33))
    with pytest.raises(SPSDKError, match="Invalid length of nonce"):
        SBV2xAdvancedParams(nonce=bytes(33))


def test_invalid_boot_image_v2():
    with pytest.raises(SPSDKError, match="Invalid dek or mac"):
        BootImageV20(
            True, kek=kek_value, advanced_params=SBV2xAdvancedParams(dek=bytes(33), mac=bytes(33))
        )
    bimg = BootImageV20(False, kek=kek_value)

    with pytest.raises(
        SPSDKError, match="Certificate block cannot be used unless SB file is signed"
    ):
        bimg.cert_block = CertBlockV1()
    bimg = BootImageV20(True, kek=bytes(31))
    bimg.cert_block = None
    with pytest.raises(SPSDKError, match="Certification block not present"):
        bimg.raw_size_without_signature

    bimg = BootImageV20(True, kek=bytes(31))
    with pytest.raises(SPSDKError, match="Certification block not present"):
        bimg.raw_size


def test_invalid_boot_image_v2_invalid_export():
    bimg = BootImageV20(True, kek=bytes(31))
    bimg._dek = bytes()
    with pytest.raises(SPSDKError, match="Invalid dek or mac"):
        bimg.export()
