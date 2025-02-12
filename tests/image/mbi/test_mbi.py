#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from typing import Optional

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import SignatureProvider
from spsdk.exceptions import SPSDKError
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.image.mbi.mbi import MasterBootImage, create_mbi_class, get_all_mbi_classes
from spsdk.image.mbi.mbi_mixin import Mbi_MixinRelocTable, MultipleImageEntry, MultipleImageTable
from spsdk.image.trustzone import TrustZone
from spsdk.utils.crypto.cert_blocks import CertBlockV1
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import load_binary, load_configuration, write_file
from spsdk.utils.schema_validator import check_config

#################################################################
# To create data sets for Master Boot Image (MBI)
# - check the tests\image\data\mbi for .cmd and .json files
#################################################################


def certificate_block(data_dir, der_file_names, index=0, chain_der_file_names=None) -> CertBlockV1:
    """
    :param data_dir: absolute path of data dir where the test keys are located
    :param der_file_names: list of filenames of the DER certificate
    :param index: of the root certificate (index to der_file_names list)
    :param chain_der_file_names: list of filenames of der certificates in chain (applied for `index`)
    :return: certificate block for testing
    """
    # read public certificate
    cert_data_list = list()
    for der_file_name in der_file_names:
        if der_file_name:
            with open(os.path.join(data_dir, "keys_and_certs", der_file_name), "rb") as f:
                cert_data_list.append(f.read())
        else:
            cert_data_list.append(None)

    # create certification block
    cert_block = CertBlockV1(build_number=1)
    cert_block.add_certificate(cert_data_list[index])
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
def test_lpc55s3x_image_version(img_ver, expected_val):
    """Test of generating of various image versions into binary MBI"""
    mbi = create_mbi_class("crc_xip", "lpc55s3x")(
        app=bytes(range(256)),
        image_version=img_ver,
    )
    data = mbi.export()[0x24:0x28]
    assert data == expected_val


def _compare_image(mbi: MasterBootImage, data_dir: str, expected_mbi_filename: str) -> bool:
    """Compare generated image with expected image

    :param mbi: master boot image instance configured to generate image data
    :param expected_mbi_filename: file name of expected image
    :return: True if data are same; False otherwise
    """
    generated_image = mbi.export()

    expected_data = load_binary(os.path.join(data_dir, expected_mbi_filename), "rb")

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
def test_plain_xip_crc_no_tz(data_dir, input_img, expected_mbi: str):
    """Test plain image with CRC and no TZ-M
    :param data_dir: absolute path, where test data are located
    :param input_img: file name of input image (binary)
    :param expected_mbi: file name of MBI image file with expected data
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()

    mbi = create_mbi_class("crc_xip", "lpc55s6x")(
        app=org_data,
        trust_zone=TrustZone.disabled(),
    )

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
def test_signed_xip_single_certificate_no_tz(data_dir, priv_key, der_certificate, expected_mbi):
    """Test signed XIP image with single certificate, different key length
    :param data_dir: absolute path, where test data are located
    :param priv_key: filename of private key used for signing
    :param der_certificate: filename of corresponding certificate in DER format
    :param expected_mbi: filename of expected bootable image
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, [der_certificate])

    priv_key = os.path.join(data_dir, "keys_and_certs", priv_key)
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = create_mbi_class("signed_xip", "rt6xx")(
        app=org_data,
        trust_zone=TrustZone.disabled(),
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
def test_signed_ram_single_certificate_no_tz(data_dir, user_key, key_store_filename, expected_mbi):
    """Test non-XIP signed image with single certificate
    :param data_dir: absolute path, where test data are located
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])

    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    key_store = None
    if key_store_filename:
        with open(os.path.join(data_dir, key_store_filename), "rb") as f:
            key_store_bin = f.read()
        key_store = KeyStore(KeySourceType.KEYSTORE, key_store_bin)

    mbi = create_mbi_class("signed_ram", "rt6xx")(
        app=org_data,
        load_address=0x12345678,
        trust_zone=TrustZone.disabled(),
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
    data_dir, keysource: KeySourceType, keystore_fn: Optional[str], ctr_iv: str, expected_mbi: str
):
    """Test encrypted image with fixed counter init vector"""
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store_bin = None
    if keystore_fn:
        with open(os.path.join(data_dir, keystore_fn), "rb") as f:
            key_store_bin = f.read()
    key_store = KeyStore(keysource, key_store_bin)
    ctr_init_vector = bytes.fromhex(ctr_iv)
    # create certification block
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    mbi = create_mbi_class("encrypted_signed_ram", "rt6xx")(
        app=org_data,
        load_address=0x12345678,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
        ctr_init_vector=ctr_init_vector,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_encrypted_random_ctr_single_certificate_no_tz(data_dir):
    """Test encrypted image with random counter init vector"""
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store = KeyStore(KeySourceType.KEYSTORE, None)
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = create_mbi_class("encrypted_signed_ram", "rt6xx")(
        app=org_data,
        load_address=0x12345678,
        trust_zone=TrustZone.disabled(),
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
    data_dir, der_certificates, root_index, expected_mbi
):
    """Test signed image with multiple certificates, different key length
    :param data_dir: absolute path, where test data are located
    :param der_certificates: list of filenames of der certificates
    :param root_index: index of root certificate
    :param expected_mbi: filename of expected bootable image
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, der_certificates, root_index)
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    mbi = create_mbi_class("signed_xip", "rt6xx")(
        app=org_data,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_signed_xip_multiple_certificates_invalid_input(data_dir):
    """Test invalid input for multiple certificates"""
    # indexed certificate is not specified
    der_file_names = [
        "selfsign_4096_v3.der.crt",
        "selfsign_3072_v3.der.crt",
        "selfsign_2048_v3.der.crt",
    ]
    with pytest.raises(IndexError):
        certificate_block(data_dir, der_file_names, 3)

    # indexed certificate is not specified
    der_file_names = [
        "selfsign_4096_v3.der.crt",
        None,
        "selfsign_3072_v3.der.crt",
        "selfsign_2048_v3.der.crt",
    ]
    with pytest.raises(SPSDKError):
        certificate_block(data_dir, der_file_names, 1)

    # public key in certificate and private key does not match
    der_file_names = ["selfsign_4096_v3.der.crt"]
    cert_block = certificate_block(data_dir, der_file_names, 0)
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    with pytest.raises(SPSDKError):
        create_mbi_class("signed_xip", "rt6xx")(
            app=bytes(range(128)),
            trust_zone=TrustZone.disabled(),
            cert_block=cert_block,
            signature_provider=signature_provider,
        ).export()

    # chain of certificates does not match
    der_file_names = ["selfsign_4096_v3.der.crt"]
    chain_certificates = ["ch3_crt2_v3.der.crt"]
    with pytest.raises(SPSDKError):
        certificate_block(data_dir, der_file_names, 0, chain_certificates)


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
    data_dir, der_certificates, chain_certificates, priv_key, expected_mbi
):
    """Test signed image with multiple certificates, different key length
    :param data_dir: absolute path, where test data are located
    :param der_certificates: list of filenames of der root certificates
    :param chain_certificates: list of filenames of der certificates
    :param priv_key: private key filename
    :param expected_mbi: filename of expected bootable image
    """
    with open(os.path.join(data_dir, "normal_boot.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, der_certificates, 0, chain_certificates)
    priv_key = os.path.join(data_dir, "keys_and_certs", priv_key)
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")

    mbi = create_mbi_class("signed_xip", "rt6xx")(
        app=org_data,
        trust_zone=TrustZone.disabled(),
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
def test_plain_xip_crc_default_tz(data_dir, input_img, expected_mbi):
    """Test plain image with CRC and default TZ-M
    :param data_dir: absolute path, where test data are located
    :param input_img: file name of input image (binary)
    :param expected_mbi: file name of MBI image file with expected data
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()

    mbi = create_mbi_class("crc_xip", "rt6xx")(
        app=org_data,
        trust_zone=TrustZone.enabled(),
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
def test_plain_ram_crc_default_tz(data_dir, input_img, load_address, expected_mbi):
    """Test plain image with CRC and default TZ-M
    :param data_dir: absolute path, where test data are located
    :param input_img: file name of input image (binary)
    :param load_address: address where the image is loaded
    :param expected_mbi: file name of MBI image file with expected data
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()

    mbi = create_mbi_class("crc_ram", "rt6xx")(
        app=org_data,
        load_address=load_address,
        trust_zone=TrustZone.enabled(),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "input_img,tz_config,family,expected_mbi",
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
            "evkmimxrt595_hello_world_xip_crc_custom_tz_mbi.bin",
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
def test_plain_xip_crc_custom_tz(data_dir, input_img, tz_config, family, expected_mbi):
    """Test plain image with CRC and custom TZ-M
    :param data_dir: absolute path, where test data are located
    :param input_img: file name of input image (binary)
    :param tz_config: file name of trust-zone configuration JSON file
    :param family: identification of the processor for conversion of trust-zone data
    :param expected_mbi: file name of MBI image file with expected data
    """
    org_data = load_binary(os.path.join(data_dir, input_img))
    # expected_data = load_binary(os.path.join(data_dir, expected_mbi))
    tz_presets = load_configuration(os.path.join(data_dir, tz_config))["trustZonePreset"]

    mbi = create_mbi_class("crc_xip", "rt6xx")(
        app=org_data,
        trust_zone=TrustZone(family=family, customizations=tz_presets),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_multiple_images_with_relocation_table(data_dir):
    """Test image that contains multiple binary images and relocation table
    :param data_dir: absolute path, where test data are located
    """
    img_data = load_binary(os.path.join(data_dir, "multicore", "normal_boot.bin"))
    img1_data = load_binary(os.path.join(data_dir, "multicore", "testfffffff.bin"))
    img2_data = load_binary(os.path.join(data_dir, "multicore", "special_boot.bin"))

    trust_zone_data = load_configuration(os.path.join(data_dir, "multicore", "rt5xxA0.yaml"))[
        "trustZonePreset"
    ]

    table = MultipleImageTable()
    table.add_entry(MultipleImageEntry(img1_data, 0x80000))
    table.add_entry(MultipleImageEntry(img2_data, 0x80600))

    mbi = create_mbi_class("crc_ram", "rt6xx")(
        app=img_data,
        app_table=table,
        load_address=0,
        trust_zone=TrustZone.custom("rt5xx", trust_zone_data),
    )

    assert _compare_image(mbi, os.path.join(data_dir, "multicore"), "expected_output.bin")


def test_loading_relocation_table(tests_root_dir, data_dir):
    """Test of relocation table mixin support."""

    class TestAppTable(Mbi_MixinRelocTable):
        def __init__(self) -> None:
            self.app = bytes(100)
            self.app_table = None
            self.search_paths = [tests_root_dir]

    test_cls = TestAppTable()
    cfg = load_configuration(os.path.join(data_dir, "test_app_table.yaml"))
    # Test validation by JSON SCHEMA
    schemas = []
    schema_cfg = get_schema_file(DatabaseManager.MBI)
    schemas.append(schema_cfg["app_table"])
    check_config(cfg, schemas, search_paths=[tests_root_dir])
    # Test Load
    test_cls.mix_load_from_config(cfg)


def test_multiple_image_entry_table_invalid():
    with pytest.raises(SPSDKError, match="Invalid destination address"):
        MultipleImageEntry(img=bytes(), dst_addr=0xFFFFFFFFA)
    with pytest.raises(SPSDKError):
        MultipleImageEntry(img=bytes(), dst_addr=0xFFFFFFFF, flags=4)


def test_multiple_image_table_invalid():
    with pytest.raises(SPSDKError, match="There must be at least one entry for export"):
        img_table = MultipleImageTable()
        img_table._entries = None
        img_table.export(start_addr=0xFFF)


def test_master_boot_image_invalid_hmac(data_dir):
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store = KeyStore(KeySourceType.KEYSTORE, None)
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = create_mbi_class("encrypted_signed_ram", "rt6xx")(
        app=org_data,
        load_address=0x12345678,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
    )
    mbi.hmac_key = None
    assert mbi.compute_hmac(data=bytes(16)) == bytes()


def test_invalid_export_mbi(data_dir):
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store_bin = None
    key_store = KeyStore(KeySourceType.KEYSTORE, key_store_bin)
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key = os.path.join(data_dir, "keys_and_certs", "selfsign_privatekey_rsa2048.pem")
    signature_provider = SignatureProvider.create(f"type=file;file_path={priv_key}")
    mbi = create_mbi_class("encrypted_signed_ram", "rt6xx")(
        app=org_data,
        load_address=0x12345678,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        signature_provider=signature_provider,
        hmac_key=user_key,
        key_store=key_store,
        ctr_init_vector=bytes(16),
    )
    mbi.signature_provider = None
    with pytest.raises(SPSDKError):
        mbi.export()
    mbi.signature_provider = signature_provider
    mbi.cert_block = None
    with pytest.raises(SPSDKError):
        mbi.export()


def test_invalid_image_base_address(data_dir):
    mbi = create_mbi_class("plain_xip", "rt6xx")()
    with pytest.raises(SPSDKError):
        mbi.load_from_config(
            load_configuration(os.path.join(data_dir, "lpc55s6x_int_xip_plain.yml"))
        )
    # test bad alignment
    mbi.app_ext_memory_align = 31
    with pytest.raises(SPSDKError):
        mbi.load_from_config(
            load_configuration(os.path.join(data_dir, "lpc55s6x_int_xip_plain.yml"))
        )


@pytest.mark.parametrize(
    "family,mbi_image",
    [
        ("mimxrt595s", "evkmimxrt595_hello_world_xip_crc_no_tz_mbi.bin"),
    ],
)
def test_parse_image_with_additional_padding(data_dir, family: str, mbi_image: str):
    with open(os.path.join(data_dir, mbi_image), "rb") as f:
        org_data = f.read()
    extra_padding = bytes(64)
    mbi = MasterBootImage.parse(family=family, data=org_data + extra_padding)
    assert isinstance(mbi, MasterBootImage)


def test_get_mbi_classes():
    mbi_classes = get_all_mbi_classes()
    for mbi in mbi_classes:
        assert issubclass(mbi, MasterBootImage)
