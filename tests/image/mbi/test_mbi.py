#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Master Boot Image (MBI) testing module.

This module contains comprehensive tests for the Master Boot Image functionality
in SPSDK, covering various image types, configurations, and validation scenarios
including plain and signed XIP images, RAM images with encryption, certificate
chain validation, Trust Zone configurations, and multi-image handling.
"""

import os
from typing import List, Optional, Type, Union

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlockV1
from spsdk.image.exceptions import SPSDKUnsupportedImageType
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.mbi.mbi_mixin import Mbi_MixinRelocTable, MultipleImageEntry, MultipleImageTable
from spsdk.image.trustzone import TrustZone
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, write_file

#################################################################
# To create data sets for Master Boot Image (MBI)
# - check the tests\image\data\mbi for .cmd and .json files
#################################################################


def certificate_block(
    data_dir: str,
    family: FamilyRevision,
    der_file_names: List[Optional[str]],
    index: int = 0,
    chain_der_file_names: Optional[List[str]] = None,
) -> CertBlockV1:
    """Create certificate block for testing purposes.

    Builds a certificate block with specified certificates and chain, validates export
    functionality, and sets up root key hashes for testing scenarios.

    :param data_dir: Absolute path to data directory containing test keys and certificates.
    :param family: Target family revision for the certificate block.
    :param der_file_names: List of DER certificate filenames, may contain None values.
    :param index: Index of the root certificate in der_file_names list.
    :param chain_der_file_names: List of DER certificate filenames to add to certificate chain.
    :return: Configured certificate block ready for testing.
    """
    # read public certificate
    cert_data_list: List[Optional[bytes]] = list()
    for der_file_name in der_file_names:
        if der_file_name:
            with open(os.path.join(data_dir, "keys_and_certs", der_file_name), "rb") as f:
                cert_data_list.append(f.read())
        else:
            cert_data_list.append(None)

    # create certification block
    cert_block = CertBlockV1(family=family, build_number=1)
    cert_data = cert_data_list[index]
    if cert_data is not None:
        cert_block.add_certificate(cert_data)
    if chain_der_file_names:
        for der_file_name in chain_der_file_names:
            with open(os.path.join(data_dir, "keys_and_certs", der_file_name), "rb") as f:
                cert_block.add_certificate(f.read())

    # add hashes
    for root_key_index, cert_data in enumerate(cert_data_list):
        if cert_data:
            cert_block.set_root_key_hash(root_key_index, Certificate.parse(cert_data))

    cert_block.export()  # check export works
    str(cert_block)  # check info works

    return cert_block


@pytest.mark.parametrize(
    "img_ver, expected_val",
    [
        (0, b"\x05\x00\x00\x00"),
        (1, b"\x05\x04\x01\x00"),
        (0x10, b"\x05\x04\x10\x00"),
        (0xFF, b"\x05\x04\xff\x00"),
    ],
)
def test_lpc55s3x_image_version(img_ver: int, expected_val: bytes) -> None:
    """Test of generating of various image versions into binary MBI.

    Validates that the Master Boot Image (MBI) correctly encodes different image version
    values into the binary format for LPC55S3x family devices. The test creates an MBI
    with a specified image version and verifies the version is properly written to the
    expected offset in the exported binary data.

    :param img_ver: Image version value to be encoded in the MBI
    :param expected_val: Expected binary representation of the image version at offset 0x24-0x28
    """
    family = FamilyRevision("lpc55s3x")
    mbi = MasterBootImage.create_mbi_class("crc_xip", family)(
        family=family,
        app=bytes(range(256)),
        image_version=img_ver,
    )
    data = mbi.export()[0x24:0x28]
    assert data == expected_val


def _compare_image(mbi: MasterBootImage, data_dir: str, expected_mbi_filename: str) -> bool:
    """Compare generated MBI image with expected reference image.

    The method exports the master boot image data and compares it with the expected
    binary data from a reference file. If the comparison fails, it writes the
    generated data to a new file for debugging purposes.

    :param mbi: Master boot image instance configured to generate image data.
    :param data_dir: Directory path containing the expected image file.
    :param expected_mbi_filename: File name of the expected reference image.
    :return: True if generated and expected data are identical; False otherwise.
    """
    generated_image = mbi.export()

    expected_data = load_binary(os.path.join(data_dir, expected_mbi_filename))

    if generated_image != expected_data:
        write_file(
            generated_image, os.path.join(data_dir, expected_mbi_filename + ".created"), "wb"
        )
        return False

    assert mbi.export() == expected_data  # check additional call still generates the same data
    return True


@pytest.mark.parametrize(
    "input_img,expected_mbi",
    [
        ("lpcxpresso55s69_led_blinky.bin", "lpc55_crc_no_tz_mbi.bin"),
        ("evkmimxrt685_hello_world.bin", "evkmimxrt685_hello_world_xip_crc_no_tz_mbi.bin"),
        ("evkmimxrt595_hello_world.bin", "evkmimxrt595_hello_world_xip_crc_no_tz_mbi.bin"),
    ],
)
def test_plain_xip_crc_no_tz(data_dir: str, input_img: str, expected_mbi: str) -> None:
    """Test plain XIP image with CRC and no TrustZone-M.

    This test verifies the creation of a Master Boot Image (MBI) for LPC55S6x family
    using CRC XIP mode without TrustZone-M support by comparing the generated image
    against expected reference data.

    :param data_dir: Absolute path to directory containing test data files.
    :param input_img: File name of the input binary image to be processed.
    :param expected_mbi: File name of the expected MBI reference file for comparison.
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()

    family = FamilyRevision("lpc55s6x")
    mbi = MasterBootImage.create_mbi_class("crc_xip", family)(family, app=org_data)

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "priv_key,der_certificate,expected_mbi",
    [
        # 2048
        (
            "selfsign_privatekey_rsa2048.pem",
            "selfsign_2048_v3.der.crt",
            "evkmimxrt685_testnormal_xip_signed2048_no_tz_mbi.bin",
        ),
        # 3072
        (
            "private_rsa3072.pem",
            "selfsign_3072_v3.der.crt",
            "evkmimxrt685_testnormal_xip_signed3072_no_tz_mbi.bin",
        ),
        # 4096
        (
            "private_rsa4096.pem",
            "selfsign_4096_v3.der.crt",
            "evkmimxrt685_testnormal_xip_signed4096_no_tz_mbi.bin",
        ),
    ],
)
def test_signed_xip_single_certificate_no_tz(
    data_dir: str, priv_key: str, der_certificate: str, expected_mbi: str
) -> None:
    """Test signed XIP image with single certificate and different key lengths.

    This test verifies the creation of a signed XIP (Execute In Place) Master Boot Image
    using a single certificate without TrustZone configuration. It validates that the
    generated MBI matches the expected reference image.

    :param data_dir: Absolute path to directory containing test data files.
    :param priv_key: Filename of the private key used for signing the image.
    :param der_certificate: Filename of the corresponding certificate in DER format.
    :param expected_mbi: Filename of the expected reference bootable image for comparison.
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    family = FamilyRevision("rt6xx")
    # create certification block
    cert_block = certificate_block(data_dir, family, [der_certificate])

    priv_key_path = os.path.join(data_dir, "keys_and_certs", priv_key)
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key_path}")
    mbi = MasterBootImage.create_mbi_class("signed_xip", family)(
        family=family,
        app=org_data,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "user_key,key_store_filename,expected_mbi",
    [
        (
            "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5",
            None,
            "evkmimxrt685_testnormal_ram_signed2048_no_tz_mbi.bin",
        ),
        (
            bytes.fromhex("E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"),
            None,
            "evkmimxrt685_testnormal_ram_signed2048_no_tz_mbi.bin",
        ),
        (
            "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5",
            "key_store_rt6xx.bin",
            "evkmimxrt685_testnormal_ram_key_store_signed2048_no_tz_mbi.bin",
        ),
    ],
)
def test_signed_ram_single_certificate_no_tz(
    data_dir: str, user_key: Union[str, bytes], key_store_filename: Optional[str], expected_mbi: str
) -> None:
    """Test non-XIP signed image with single certificate.

    This test verifies the creation of a signed RAM-based Master Boot Image (MBI)
    using a single certificate without TrustZone configuration. It loads test data,
    creates a certificate block, sets up signature provider, and validates the
    resulting MBI against expected output.

    :param data_dir: Absolute path where test data are located.
    :param user_key: HMAC key for image authentication, either as file path or raw bytes.
    :param key_store_filename: Optional filename of the key store file in data directory.
    :param expected_mbi: Expected MBI filename for comparison validation.
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    family = FamilyRevision("rt6xx")
    # create certification block
    cert_block = certificate_block(data_dir, family, ["selfsign_2048_v3.der.crt"])

    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    key_store = None
    if key_store_filename:
        with open(os.path.join(data_dir, key_store_filename), "rb") as f:
            key_store_bin = f.read()
        key_store = KeyStore(KeySourceType.KEYSTORE, key_store_bin)

    mbi = MasterBootImage.create_mbi_class("signed_ram", family)(
        family=family,
        app=org_data,
        load_address=0x12345678,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "keysource,keystore_fn,ctr_iv,expected_mbi",
    [
        # key source = KEYSTORE; key store empty
        (
            KeySourceType.KEYSTORE,
            None,
            "8de432f2283a1cb8bb818d41bf9dfafb",
            "evkmimxrt685_testnormal_ram_encrypted2048_none_keystore_no_tz_mbi.bin",
        ),
        # key source = OTP
        (
            KeySourceType.OTP,
            None,
            "fff5a54ee37de8f9606c048d941588df",
            "evkmimxrt685_testnormal_ram_encrypted2048_otp_no_tz_mbi.bin",
        ),
        # key source = KEYSTORE; key store non-empty
        (
            KeySourceType.KEYSTORE,
            "key_store_rt6xx.bin",
            "0691d67713375bf6effcfb2c7d83321e",
            "evkmimxrt685_testnormal_ram_encrypted2048_keystore_no_tz_mbi.bin",
        ),
    ],
)
def test_encrypted_ram_single_certificate_no_tz(
    data_dir: str,
    keysource: KeySourceType,
    keystore_fn: Optional[str],
    ctr_iv: str,
    expected_mbi: str,
) -> None:
    """Test encrypted RAM image with single certificate and no TrustZone.

    This test verifies the creation of an encrypted and signed Master Boot Image (MBI)
    for RAM execution using a single certificate without TrustZone configuration.
    The test uses a fixed counter initialization vector for encryption and validates
    the generated image against expected output.

    :param data_dir: Directory path containing test data files including boot binary,
                     certificates, and keys
    :param keysource: Type of key source for the key store configuration
    :param keystore_fn: Optional filename of the key store binary file, if None no
                        key store file is loaded
    :param ctr_iv: Hexadecimal string representation of the counter initialization
                   vector for encryption
    :param expected_mbi: Filename of the expected MBI output for comparison
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store_bin = None
    if keystore_fn:
        with open(os.path.join(data_dir, keystore_fn), "rb") as f:
            key_store_bin = f.read()
    key_store = KeyStore(keysource, key_store_bin)
    ctr_init_vector = bytes.fromhex(ctr_iv)
    family = FamilyRevision("rt6xx")
    # create certification block
    cert_block = certificate_block(data_dir, family, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    mbi = MasterBootImage.create_mbi_class("encrypted_signed_ram", family)(
        family=family,
        app=org_data,
        load_address=0x12345678,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
        ctr_init_vector=ctr_init_vector,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_encrypted_random_ctr_single_certificate_no_tz(data_dir: str) -> None:
    """Test encrypted MBI image with random counter initialization vector and single certificate.

    This test verifies the creation and export of an encrypted and signed Master Boot Image
    using a random counter initialization vector, single self-signed certificate, and no
    TrustZone configuration for the RT6xx family.

    :param data_dir: Path to the directory containing test data files including boot binary,
                     certificates, and private keys
    :raises AssertionError: If MBI export fails or returns invalid data
    :raises FileNotFoundError: If required test data files are not found
    :raises SPSDKError: If MBI creation or configuration fails
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store = KeyStore(KeySourceType.KEYSTORE, None)
    family = FamilyRevision("rt6xx")
    cert_block = certificate_block(data_dir, family, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = MasterBootImage.create_mbi_class("encrypted_signed_ram", family)(
        family=family,
        app=org_data,
        load_address=0x12345678,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
    )
    assert mbi.export()


@pytest.mark.parametrize(
    "der_certificates,root_index,expected_mbi",
    [
        # 3 certificates
        (
            ["selfsign_4096_v3.der.crt", "selfsign_3072_v3.der.crt", "selfsign_2048_v3.der.crt"],
            2,
            "evkmimxrt685_testnormal_xip_3_certs_no_tz_mbi.bin",
        ),
        # 4 certificates
        (
            [
                "selfsign_4096_v3.der.crt",
                "selfsign_3072_v3.der.crt",
                "selfsign_2048_v3.der.crt",
                "selfsign_3072_v3.der.crt",
            ],
            2,
            "evkmimxrt685_testnormal_xip_4_certs_no_tz_mbi.bin",
        ),
        # 2 certificates (first and last)
        (
            ["selfsign_4096_v3.der.crt", None, None, "selfsign_2048_v3.der.crt"],
            3,
            "evkmimxrt685_testnormal_xip_2_certs_no_tz_mbi.bin",
        ),
    ],
)
def test_signed_xip_multiple_certificates_no_tz(
    data_dir: str, der_certificates: list, root_index: int, expected_mbi: str
) -> None:
    """Test signed XIP image with multiple certificates and different key lengths.

    Validates the creation of a signed XIP (Execute In Place) Master Boot Image
    using multiple DER certificates with varying key lengths, without TrustZone
    configuration.

    :param data_dir: Absolute path to directory containing test data files
    :param der_certificates: List of DER certificate filenames to be used
    :param root_index: Index specifying which certificate serves as root certificate
    :param expected_mbi: Filename of the expected Master Boot Image for comparison
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    family = FamilyRevision("rt6xx")
    # create certification block
    cert_block = certificate_block(data_dir, family, der_certificates, root_index)
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    mbi = MasterBootImage.create_mbi_class("signed_xip", family)(
        family=family,
        app=org_data,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_signed_xip_multiple_certificates_invalid_input(data_dir: str) -> None:
    """Test invalid input scenarios for multiple certificates in signed XIP MBI.

    This test validates error handling for various invalid certificate configurations
    including out-of-bounds certificate indexing, None certificate entries,
    mismatched public/private key pairs, and invalid certificate chains.

    :param data_dir: Path to directory containing test data files including certificates and keys
    :raises IndexError: When certificate index is out of bounds
    :raises SPSDKError: When certificate configuration is invalid (None entries, key mismatches, or chain validation failures)
    """
    family = FamilyRevision("rt6xx")
    # indexed certificate is not specified
    der_file_names: list[Optional[str]] = [
        "selfsign_4096_v3.der.crt",
        "selfsign_3072_v3.der.crt",
        "selfsign_2048_v3.der.crt",
    ]
    with pytest.raises(IndexError):
        certificate_block(data_dir, family, der_file_names, 3)  # type: ignore

    # indexed certificate is not specified
    der_file_names = [
        "selfsign_4096_v3.der.crt",
        None,
        "selfsign_3072_v3.der.crt",
        "selfsign_2048_v3.der.crt",
    ]
    with pytest.raises(SPSDKError):
        certificate_block(data_dir, family, der_file_names, 1)

    # public key in certificate and private key does not match
    der_file_names = ["selfsign_4096_v3.der.crt"]
    cert_block = certificate_block(data_dir, family, der_file_names, 0)
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    with pytest.raises(SPSDKError):
        MasterBootImage.create_mbi_class("signed_xip", family)(
            family=family,
            app=bytes(range(128)),
            trust_zone=None,
            cert_block=cert_block,
            signature_provider=signature_provider,
        ).export()

    # chain of certificates does not match
    der_file_names = ["selfsign_4096_v3.der.crt"]
    chain_certificates = ["ch3_crt2_v3.der.crt"]
    with pytest.raises(SPSDKError):
        certificate_block(data_dir, family, der_file_names, 0, chain_certificates)


@pytest.mark.parametrize(
    "der_certificates,chain_certificates,priv_key,expected_mbi",
    [
        # 2 certificates in chain
        (
            ["ca0_v3.der.crt"],
            ["crt_v3.der.crt"],
            "crt_privatekey_rsa2048.pem",
            "evkmimxrt685_testnormal_xip_chain_2_no_tz_mbi.bin",
        ),
        # 3 certificates in chain
        (
            ["ca0_v3.der.crt"],
            ["ch3_crt_v3.der.crt", "ch3_crt2_v3.der.crt"],
            "crt2_privatekey_rsa2048.pem",
            "evkmimxrt685_testnormal_xip_chain_3_no_tz_mbi.bin",
        ),
    ],
)
def test_signed_xip_certificates_chain_no_tz(
    data_dir: str,
    der_certificates: list,
    chain_certificates: list,
    priv_key: str,
    expected_mbi: str,
) -> None:
    """Test signed XIP image with multiple certificates and different key lengths.

    This test verifies the creation of a signed XIP (Execute In Place) Master Boot Image
    using a certificate chain with multiple certificates of varying key lengths, without
    TrustZone configuration.

    :param data_dir: Absolute path to directory containing test data files.
    :param der_certificates: List of DER root certificate filenames.
    :param chain_certificates: List of DER certificate chain filenames.
    :param priv_key: Private key filename for signing the image.
    :param expected_mbi: Expected Master Boot Image filename for comparison.
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    family = FamilyRevision("rt6xx")
    # create certification block
    cert_block = certificate_block(data_dir, family, der_certificates, 0, chain_certificates)
    priv_key = os.path.join(data_dir, "keys_and_certs", priv_key)
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    mbi = MasterBootImage.create_mbi_class("signed_xip", family)(
        family=family,
        app=org_data,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "input_img,expected_mbi",
    [
        ("lpcxpresso55s69_led_blinky.bin", "lpc55_crc_default_tz_mbi.bin"),
        ("evkmimxrt685_hello_world.bin", "evkmimxrt685_hello_world_xip_crc_default_tz_mbi.bin"),
        ("evkmimxrt595_hello_world.bin", "evkmimxrt595_hello_world_xip_crc_default_tz_mbi.bin"),
    ],
)
def test_plain_xip_crc_default_tz(data_dir: str, input_img: str, expected_mbi: str) -> None:
    """Test plain image with CRC and default TZ-M.

    This test verifies that a Master Boot Image (MBI) can be correctly created
    with CRC protection and default TrustZone-M configuration for RT6xx family.

    :param data_dir: Absolute path where test data are located.
    :param input_img: File name of input image (binary).
    :param expected_mbi: File name of MBI image file with expected data.
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()
    family = FamilyRevision("rt6xx")
    mbi = MasterBootImage.create_mbi_class("crc_xip", family)(
        family=family,
        app=org_data,
        trust_zone=TrustZone(FamilyRevision("rt6xx")),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "input_img,load_address,expected_mbi",
    [
        (
            "evkmimxrt595_hello_world_ram.bin",
            0x20080000,
            "evkmimxrt595_hello_world_ram_crc_default_tz_mbi.bin",
        ),
    ],
)
def test_plain_ram_crc_default_tz(
    data_dir: str, input_img: str, load_address: int, expected_mbi: str
) -> None:
    """Test plain image with CRC and default TZ-M.

    This test validates the creation of a Master Boot Image (MBI) with CRC protection
    and default TrustZone-M configuration for RT6xx family devices.

    :param data_dir: Absolute path where test data are located.
    :param input_img: File name of input image (binary).
    :param load_address: Address where the image is loaded.
    :param expected_mbi: File name of MBI image file with expected data.
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()
    family = FamilyRevision("rt6xx")
    mbi = MasterBootImage.create_mbi_class("crc_ram", family)(
        family=family,
        app=org_data,
        load_address=load_address,
        trust_zone=TrustZone(family),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "input_img,tz_config,family_str,expected_mbi",
    [
        (
            "lpcxpresso55s06_hello_world.bin",
            "lpc55s0xA0.yaml",
            "lpc55s0x",
            "lpc55s0x_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "lpcxpresso55s16_hello_world.bin",
            "lpc55s1xA0.yaml",
            "lpc55s1x",
            "lpc55s1x_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "lpcxpresso55s36_hello_world.bin",
            "lpc55s3xA1.yaml",
            "lpc55s3x",
            "lpc55s3x_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "lpcxpresso55s69_led_blinky.bin",
            "lpc55s6xA1.yaml",
            "lpc55s6x",
            "lpc55_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt685_hello_world.bin",
            "rt6xx_test.yaml",
            "rt6xx",
            "evkmimxrt685_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt595_hello_world.bin",
            "rt5xxA0.yaml",
            "rt5xx",
            "evkmimxrt595_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt595_hello_world.bin",
            "rt5xx_empty.yaml",
            "rt5xx",
            "evkmimxrt595_hello_world_xip_crc_default_tz_mbi.bin",
        ),
        (
            "evkmimxrt595_hello_world.bin",
            "rt5xx_few.yaml",
            "rt5xx",
            "evkmimxrt595_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "mcxn9xxevk_hello_world.bin",
            "mcxn9xxA1.yaml",
            "mcxn9xx",
            "mcxn9xx_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "kw45b41z_hello_world.bin",
            "kw45xxA1.yaml",
            "kw45xx",
            "kw45b41z_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "k32w148_hello_world.bin",
            "k32w1xxA1.yaml",
            "k32w1xx",
            "k32w148_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "rdrw610_hello_world.bin",
            "rw61xA1.yaml",
            "rw61x",
            "rw61x_a1_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
    ],
)
def test_plain_xip_crc_custom_tz(
    data_dir: str, input_img: str, tz_config: str, family_str: str, expected_mbi: str
) -> None:
    """Test plain image with CRC and custom TZ-M.

    This test verifies the creation of a Master Boot Image (MBI) with CRC protection
    and custom TrustZone-M configuration by comparing the generated image against
    expected reference data.

    :param data_dir: Absolute path where test data are located.
    :param input_img: File name of input image (binary).
    :param tz_config: File name of trust-zone configuration JSON file.
    :param family_str: Identification of the processor for conversion of trust-zone data.
    :param expected_mbi: File name of MBI image file with expected data.
    """
    org_data = load_binary(os.path.join(data_dir, input_img))
    # expected_data = load_binary(os.path.join(data_dir, expected_mbi))
    tz_cfg = Config.create_from_file(os.path.join(data_dir, tz_config))
    family = FamilyRevision(family_str)
    mbi = MasterBootImage.create_mbi_class("crc_xip", family)(
        family=family,
        app=org_data,
        trust_zone=TrustZone.load_from_config(tz_cfg),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_multiple_images_with_relocation_table(data_dir: str) -> None:
    """Test image that contains multiple binary images and relocation table.

    This test verifies the creation and validation of a Master Boot Image (MBI) that
    includes multiple binary images with a relocation table. It loads test data,
    creates a multiple image table with entries, configures trust zone settings,
    and validates the generated MBI against expected output.

    :param data_dir: Absolute path to directory containing test data files.
    """
    img_data = load_binary(os.path.join(data_dir, "multicore", "normal_boot.bin"))
    img1_data = load_binary(os.path.join(data_dir, "multicore", "testfffffff.bin"))
    img2_data = load_binary(os.path.join(data_dir, "multicore", "special_boot.bin"))

    trust_zone_config = Config.create_from_file(os.path.join(data_dir, "multicore", "rt5xxA0.yaml"))

    table = MultipleImageTable()
    table.add_entry(MultipleImageEntry(img1_data, 0x80000))
    table.add_entry(MultipleImageEntry(img2_data, 0x80600))

    family = FamilyRevision("rt6xx")
    mbi = MasterBootImage.create_mbi_class("crc_ram", family)(
        family=family,
        app=img_data,
        app_table=table,
        load_address=0,
        trust_zone=TrustZone.load_from_config(trust_zone_config),
    )

    assert _compare_image(mbi, os.path.join(data_dir, "multicore"), "expected_output.bin")


def test_loading_relocation_table(tests_root_dir: str, data_dir: str) -> None:
    """Test relocation table mixin support functionality.

    This test verifies that the Mbi_MixinRelocTable class can properly load
    and validate relocation table configuration from a YAML file, including
    JSON schema validation and configuration loading through the mixin.

    :param tests_root_dir: Root directory path for test files and resources
    :param data_dir: Directory path containing test data files including YAML configuration
    """

    class TestAppTable(Mbi_MixinRelocTable):
        """Test helper class for MBI application table functionality.

        This class provides a test fixture that inherits from Mbi_MixinRelocTable
        to facilitate testing of MBI (Master Boot Image) application table operations.
        It sets up a controlled test environment with predefined application data
        and search paths for consistent testing scenarios.
        """

        def __init__(self) -> None:
            """Initialize test MBI object with default values.

            Sets up a test instance with a 100-byte application data buffer,
            no application table, and search paths pointing to the tests root directory.
            """
            self.app = bytes(100)
            self.app_table = None
            self.search_paths = [tests_root_dir]

    test_cls = TestAppTable()
    cfg = Config.create_from_file(os.path.join(data_dir, "test_app_table.yaml"))
    cfg.search_paths.append(tests_root_dir)
    # Test validation by JSON SCHEMA
    schemas = []
    schema_cfg = get_schema_file(DatabaseManager.MBI)
    schemas.append(schema_cfg["app_table"])
    cfg.check(schemas)
    # Test Load
    test_cls.mix_load_from_config(cfg)


def test_multiple_image_entry_table_invalid() -> None:
    """Test invalid parameters for MultipleImageEntry constructor.

    Verifies that MultipleImageEntry raises appropriate SPSDKError exceptions
    when initialized with invalid destination addresses or flags.

    :raises SPSDKError: When destination address exceeds valid range or invalid flags are provided.
    """
    with pytest.raises(SPSDKError, match="Invalid destination address"):
        MultipleImageEntry(img=bytes(), dst_addr=0xFFFFFFFFA)
    with pytest.raises(SPSDKError):
        MultipleImageEntry(img=bytes(), dst_addr=0xFFFFFFFF, flags=4)


def test_multiple_image_table_invalid() -> None:
    """Test that MultipleImageTable export raises error when entries is None.

    Verifies that attempting to export a MultipleImageTable with no entries
    (entries set to None) raises an SPSDKError with appropriate error message.

    :raises SPSDKError: When there are no entries available for export.
    """
    with pytest.raises(SPSDKError, match="There must be at least one entry for export"):
        img_table = MultipleImageTable()
        img_table._entries = None  # type: ignore
        img_table.export(start_addr=0xFFF)


def test_master_boot_image_invalid_hmac(data_dir: str) -> None:
    """Test master boot image with invalid HMAC configuration.

    This test verifies that when the HMAC key is set to None after MBI creation,
    the compute_hmac method returns empty bytes instead of raising an exception.
    The test creates an encrypted signed RAM MBI with proper configuration and
    then invalidates the HMAC key to test error handling behavior.

    :param data_dir: Directory path containing test data files and certificates
    """
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store = KeyStore(KeySourceType.KEYSTORE, None)
    family = FamilyRevision("rt6xx")
    cert_block = certificate_block(data_dir, family, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = MasterBootImage.create_mbi_class("encrypted_signed_ram", family)(
        family=family,
        app=org_data,
        load_address=0x12345678,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
    )
    mbi.hmac_key = None  # type: ignore
    assert mbi.compute_hmac(data=bytes(16)) == bytes()  # type: ignore


def test_invalid_export_mbi(data_dir: str) -> None:
    """Test invalid MBI export scenarios.

    This test verifies that MasterBootImage export fails appropriately when
    required components are missing or invalid. It tests two failure cases:
    missing signature provider and missing certificate block.

    :param data_dir: Directory path containing test data files and certificates
    :raises SPSDKError: When MBI export fails due to missing required components
    """
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store_bin = None
    key_store = KeyStore(KeySourceType.KEYSTORE, key_store_bin)
    family = FamilyRevision("rt6xx")
    cert_block = certificate_block(data_dir, family, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = MasterBootImage.create_mbi_class("encrypted_signed_ram", family)(
        family=family,
        app=org_data,
        load_address=0x12345678,
        trust_zone=None,
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
        ctr_init_vector=bytes(16),
    )
    mbi.signature_provider = None  # type: ignore
    with pytest.raises(SPSDKError):
        mbi.export()
    mbi.signature_provider = signature_provider  # type: ignore
    mbi.cert_block = None
    with pytest.raises(SPSDKError):
        mbi.export()


def test_invalid_image_base_address(data_dir: str) -> None:
    """Test invalid image base address configuration for MBI.

    Verifies that SPSDKError is raised when loading MBI configuration with
    invalid image base address and when app_ext_memory_align is set to
    an invalid alignment value.

    :param data_dir: Directory path containing test data files
    :raises SPSDKError: When invalid image base address or alignment is used
    """
    family = FamilyRevision("rt6xx")
    mbi = MasterBootImage.create_mbi_class("plain_xip", family)(family)
    with pytest.raises(SPSDKError):
        mbi.load_from_config(
            Config.create_from_file(os.path.join(data_dir, "lpc55s6x_int_xip_plain.yml"))
        )
    # test bad alignment
    mbi.app_ext_memory_align = 31  # type: ignore
    with pytest.raises(SPSDKError):
        mbi.load_from_config(
            Config.create_from_file(os.path.join(data_dir, "lpc55s6x_int_xip_plain.yml"))
        )


@pytest.mark.parametrize(
    "family,mbi_image",
    [
        (FamilyRevision("mimxrt595s"), "evkmimxrt595_hello_world_xip_crc_no_tz_mbi.bin"),
    ],
)
def test_parse_image_with_additional_padding(
    data_dir: str, family: FamilyRevision, mbi_image: str
) -> None:
    """Test parsing MBI image with additional padding bytes.

    Verifies that the MasterBootImage parser can correctly handle image data
    that contains extra padding bytes beyond the actual image content.

    :param data_dir: Directory path containing test data files.
    :param family: Target MCU family and revision for parsing.
    :param mbi_image: Filename of the MBI image file to test.
    """
    with open(os.path.join(data_dir, mbi_image), "rb") as f:
        org_data = f.read()
    extra_padding = bytes(64)
    mbi = MasterBootImage.parse(family=family, data=org_data + extra_padding)
    assert isinstance(mbi, MasterBootImage)


@pytest.mark.parametrize(
    "name,expected_auth,expected_target",
    [
        ("plain_xip", "plain", "xip"),
        ("crc_xip", "crc", "xip"),
        ("signed_xip", "signed", "xip"),
        ("nxp_signed_xip", "signed-nxp", "xip"),
        ("plain_ram", "plain", "load-to-ram"),
    ],
)
def test_parse_name(name: str, expected_auth: str, expected_target: str) -> None:
    """Test parsing of MasterBootImage name into authentication and target components.

    Validates that the _parse_name method correctly extracts authentication type
    and target information from a given name string.

    :param name: Input name string to be parsed.
    :param expected_auth: Expected authentication type result.
    :param expected_target: Expected target information result.
    """
    auth, target = MasterBootImage._parse_name(name)
    assert auth == expected_auth
    assert target == expected_target


@pytest.mark.parametrize(
    "config,expected_target,expected_auth,expected_exception",
    [
        # Valid configurations
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "xip",
                "outputImageAuthenticationType": "plain",
            },
            "xip",
            "plain",
            None,
        ),
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "load-to-ram",
                "outputImageAuthenticationType": "signed",
            },
            "load-to-ram",
            "signed",
            None,
        ),
        (
            {
                "family": "lpc55s6x",
                "outputImageExecutionTarget": "Internal flash (XIP)",
                "outputImageAuthenticationType": "CRC",
            },
            "xip",
            "crc",
            None,
        ),
        # Test XIP aliases
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "External Flash (XIP)",
                "outputImageAuthenticationType": "plain",
            },
            "xip",
            "plain",
            None,
        ),
        # Test RAM aliases
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "RAM",
                "outputImageAuthenticationType": "plain",
            },
            "load-to-ram",
            "plain",
            None,
        ),
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "ram",
                "outputImageAuthenticationType": "Plain",
            },
            "load-to-ram",
            "plain",
            None,
        ),
        # Test authentication aliases
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "xip",
                "outputImageAuthenticationType": "Signed",
            },
            "xip",
            "signed",
            None,
        ),
        # Invalid image type (not in IMAGE_TYPES)
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "invalid_target_type",
                "outputImageAuthenticationType": "plain",
            },
            None,
            None,
            SPSDKUnsupportedImageType,
        ),
        # Invalid execution target (not in MAP_IMAGE_TARGETS)
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "flash",
                "outputImageAuthenticationType": "plain",
            },
            None,
            None,
            SPSDKUnsupportedImageType,
        ),
        # Invalid authentication type (not in MAP_AUTHENTICATIONS)
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "xip",
                "outputImageAuthenticationType": "custom_auth",
            },
            None,
            None,
            SPSDKUnsupportedImageType,
        ),
        # Missing outputImageExecutionTarget
        (
            {
                "family": "rt6xx",
                "outputImageAuthenticationType": "plain",
            },
            None,
            None,
            SPSDKUnsupportedImageType,
        ),
        # Missing outputImageAuthenticationType - will fail at get_key_by_val
        (
            {
                "family": "rt6xx",
                "outputImageExecutionTarget": "xip",
            },
            None,
            None,
            SPSDKUnsupportedImageType,
        ),
        (
            {
                "family": "kw47xx",
                "outputImageExecutionTarget": "xip",
                "outputImageAuthenticationType": "nbu-signed",
            },
            "xip",
            "nbu-signed",
            None,
        ),
        (
            {
                "family": "kw47xx",
                "outputImageExecutionTarget": "xip",
                "outputImageAuthenticationType": "NBU Signed",
            },
            "xip",
            "nbu-signed",
            None,
        ),
        (
            {
                "family": "kw47xx",
                "outputImageExecutionTarget": "Internal flash (XIP)",
                "outputImageAuthenticationType": "nbu_signed",
            },
            "xip",
            "nbu-signed",
            None,
        ),
    ],
)
def test_get_mbi_class(
    config: dict[str, str],
    expected_target: Optional[str],
    expected_auth: Optional[str],
    expected_exception: Optional[Type[Exception]],
) -> None:
    """Test get_mbi_class method with various configurations.

    This test validates the get_mbi_class method behavior for:
    - Valid configurations with different execution targets and authentication types
    - Various aliases for targets (xip, RAM, Internal/External Flash)
    - Various aliases for authentication types (plain, CRC, signed)
    - Invalid image types not in IMAGE_TYPES list
    - Invalid execution targets not defined in MAP_IMAGE_TARGETS
    - Invalid authentication types not defined in MAP_AUTHENTICATIONS
    - Missing required configuration keys
    - Unsupported target-authentication combinations for specific families

    :param config: Configuration dictionary with family, target, and authentication
    :param expected_target: Expected IMAGE_TARGET value for valid configs
    :param expected_auth: Expected IMAGE_AUTHENTICATIONS value for valid configs
    :param expected_exception: Expected exception type for invalid configs
    :param expected_error_msg: Expected error message substring for invalid configs
    """
    if expected_exception:
        with pytest.raises(expected_exception):
            MasterBootImage.get_mbi_class(config)
    else:
        mbi_cls = MasterBootImage.get_mbi_class(config)
        assert mbi_cls.IMAGE_TARGET == expected_target
        assert mbi_cls.IMAGE_AUTHENTICATIONS == expected_auth
