#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import json
import os
from typing import Optional

import pytest

from spsdk.image import MasterBootImage, MasterBootImageType, MultipleImageTable, MultipleImageEntry
from spsdk.image import TrustZone
from spsdk.image.keystore import KeySourceType, KeyStore
from spsdk.utils.crypto import CertBlockV2, Certificate
from spsdk.utils.misc import load_binary


#################################################################
# To create data sets for Master Boot Image (MBI)
# - check the tests\image\data\mbi for .cmd and .json files
# - usage of elftosb-gui is highly encouraged
#################################################################


def certificate_block(data_dir, der_file_names, index=0, chain_der_file_names=None) -> CertBlockV2:
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
    cert_block = CertBlockV2(build_number=1)
    cert_block.add_certificate(cert_data_list[index])
    if chain_der_file_names:
        for der_file_name in chain_der_file_names:
            with open(os.path.join(data_dir, "keys_and_certs", der_file_name), "rb") as f:
                cert_block.add_certificate(f.read())

    # add hashes
    for root_key_index, cert_data in enumerate(cert_data_list):
        if cert_data:
            cert_block.set_root_key_hash(root_key_index, Certificate(cert_data))

    cert_block.export()  # check export works
    cert_block.info()  # check info works

    return cert_block


def _load_private_key(data_dir: str, filename: str) -> bytes:
    """Load PEM private key from data_dir

    :param filename: private key file name to load
    :return: private key as binary data in PEM format, decrypted
    """
    return load_binary(os.path.join(data_dir, "keys_and_certs", filename))


def test_master_boot_image_type():
    for image_type in MasterBootImageType.tags():
        # either XIP or RAM
        if MasterBootImageType.is_xip(image_type):
            assert not MasterBootImageType.is_copied_to_ram(image_type)
        else:
            assert MasterBootImageType.is_copied_to_ram(image_type)
        # CRC
        assert MasterBootImageType.has_crc(image_type) == (
            "CRC" in MasterBootImageType.name(image_type)
        )
        if MasterBootImageType.has_crc(image_type):
            assert not MasterBootImageType.is_signed(image_type)
            assert not MasterBootImageType.is_encrypted(image_type)
            assert not MasterBootImageType.has_hmac(image_type)
        # signed
        assert MasterBootImageType.is_signed(image_type) == (
            "SIGN" in MasterBootImageType.name(image_type).upper()
            or MasterBootImageType.is_encrypted(image_type)
        )
        if MasterBootImageType.is_signed(image_type):
            assert not MasterBootImageType.has_crc(image_type)
        # encrypted
        assert MasterBootImageType.is_encrypted(image_type) == (
            "ENCR" in MasterBootImageType.name(image_type).upper()
        )
        if MasterBootImageType.is_encrypted(image_type):
            assert MasterBootImageType.is_signed(image_type)
            assert MasterBootImageType.is_copied_to_ram(image_type)
            assert MasterBootImageType.has_hmac(image_type)
            assert not MasterBootImageType.has_crc(image_type)
        # hmac
        if MasterBootImageType.has_hmac(image_type):
            assert MasterBootImageType.is_signed(image_type)
            assert MasterBootImageType.is_copied_to_ram(image_type)
            assert not MasterBootImageType.has_crc(image_type)


def test_invalid_master_boot_image_params(data_dir):
    with pytest.raises(TypeError):
        # noinspection PyTypeChecker
        MasterBootImage(app=5)
    # load_addr must not be negative
    with pytest.raises(AssertionError):
        MasterBootImage(
            app=bytes(range(64)), load_addr=-1, image_type=MasterBootImageType.CRC_XIP_IMAGE
        )

    # certificate block is supported for signed images
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)), load_addr=0, image_type=MasterBootImageType.SIGNED_RAM_IMAGE
        )
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)), load_addr=0, image_type=MasterBootImageType.SIGNED_XIP_IMAGE
        )

    # hmac_key must be provided for load-to-ram image
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key_pem_data = _load_private_key(data_dir, "selfsign_privatekey_rsa2048.pem")
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.SIGNED_RAM_IMAGE,
            cert_block=cert_block,
            priv_key_pem_data=priv_key_pem_data,
        )
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.SIGNED_RAM_IMAGE,
            cert_block=cert_block,
            priv_key_pem_data=priv_key_pem_data,
            key_store=KeyStore(KeySourceType.OTP),
        )
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.SIGNED_RAM_IMAGE,
            cert_block=cert_block,
            priv_key_pem_data=priv_key_pem_data,
            key_store=KeyStore(KeySourceType.KEYSTORE),
        )
    # hmac_key (or key_store) cannot be provided for XIP image
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
            cert_block=cert_block,
            priv_key_pem_data=priv_key_pem_data,
            hmac_key=bytes(range(32)),
        )
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
            cert_block=cert_block,
            priv_key_pem_data=priv_key_pem_data,
            key_store=KeyStore(KeySourceType.KEYSTORE),
        )

    # app_table can be specified only for RAM images
    with pytest.raises(ValueError):
        app_table = MultipleImageTable()
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.CRC_XIP_IMAGE,
            app_table=app_table,
        )
    # app_table is empty
    with pytest.raises(ValueError):
        app_table = MultipleImageTable()
        MasterBootImage(
            app=bytes(range(64)),
            load_addr=0,
            image_type=MasterBootImageType.CRC_RAM_IMAGE,
            app_table=app_table,
        )

    # error if image len is not enough
    with pytest.raises(ValueError):
        MasterBootImage(app=bytes(range(32)), load_addr=0).export()


def _compare_image(mbi: MasterBootImage, data_dir: str, expected_mbi_filename: str) -> bool:
    """Compare generated image with expected image

    :param mbi: master boot image instance configured to generate image data
    :param expected_mbi_filename: file name of expected image
    :return: True if data are same; False otherwise
    """
    generated_image = mbi.export()

    with open(os.path.join(data_dir, expected_mbi_filename), "rb") as f:
        expected_data = f.read()

    if generated_image != expected_data:
        with open(os.path.join(data_dir, expected_mbi_filename + ".created"), "wb") as f:
            f.write(generated_image)
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

    mbi = MasterBootImage(
        app=org_data,
        load_addr=0,
        image_type=MasterBootImageType.CRC_XIP_IMAGE,
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
            "evkmimxrt685_testfffffff_xip_signed2048_no_tz_mbi.bin",
        ),
        # 3072
        (
            "private_rsa3072.pem",
            "selfsign_3072_v3.der.crt",
            "evkmimxrt685_testfffffff_xip_signed3072_no_tz_mbi.bin",
        ),
        # 4096
        (
            "private_rsa4096.pem",
            "selfsign_4096_v3.der.crt",
            "evkmimxrt685_testfffffff_xip_signed4096_no_tz_mbi.bin",
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
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, [der_certificate])
    priv_key_pem_data = _load_private_key(data_dir, priv_key)

    mbi = MasterBootImage(
        app=org_data,
        load_addr=0,
        image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "user_key,key_store_filename,expected_mbi",
    [
        (
            "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5",
            None,
            "evkmimxrt685_testfffffff_ram_signed2048_no_tz_mbi.bin",
        ),
        (
            bytes.fromhex("E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"),
            None,
            "evkmimxrt685_testfffffff_ram_signed2048_no_tz_mbi.bin",
        ),
        (
            "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5",
            "key_store_rt6xx.bin",
            "evkmimxrt685_testfffffff_ram_key_store_signed2048_no_tz_mbi.bin",
        ),
    ],
)
def test_signed_ram_single_certificate_no_tz(data_dir, user_key, key_store_filename, expected_mbi):
    """Test non-XIP signed image with single certificate
    :param data_dir: absolute path, where test data are located
    """
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key_pem_data = _load_private_key(data_dir, "selfsign_privatekey_rsa2048.pem")
    key_store = None
    if key_store_filename:
        with open(os.path.join(data_dir, key_store_filename), "rb") as f:
            key_store_bin = f.read()
        key_store = KeyStore(KeySourceType.KEYSTORE, key_store_bin)

    mbi = MasterBootImage(
        app=org_data,
        image_type=MasterBootImageType.SIGNED_RAM_IMAGE,
        load_addr=0x12345678,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
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
            "evkmimxrt685_testfffffff_ram_encrypted2048_none_keystore_no_tz_mbi.bin",
        ),
        # key source = OTP
        (
            KeySourceType.OTP,
            None,
            "fff5a54ee37de8f9606c048d941588df",
            "evkmimxrt685_testfffffff_ram_encrypted2048_otp_no_tz_mbi.bin",
        ),
        # key source = KEYSTORE; key store non-empty
        (
            KeySourceType.KEYSTORE,
            "key_store_rt6xx.bin",
            "0691d67713375bf6effcfb2c7d83321e",
            "evkmimxrt685_testfffffff_ram_encrypted2048_keystore_no_tz_mbi.bin",
        ),
    ],
)
def test_encrypted_ram_single_certificate_no_tz(
    data_dir, keysource: KeySourceType, keystore_fn: Optional[str], ctr_iv: str, expected_mbi: str
):
    """Test encrypted image with fixed counter init vector"""
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
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
    priv_key_pem_data = _load_private_key(data_dir, "selfsign_privatekey_rsa2048.pem")

    mbi = MasterBootImage(
        app=org_data,
        image_type=MasterBootImageType.ENCRYPTED_RAM_IMAGE,
        load_addr=0x12345678,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
        hmac_key=user_key,
        key_store=key_store,
        ctr_init_vector=ctr_init_vector,
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_encrypted_random_ctr_single_certificate_no_tz(data_dir):
    """Test encrypted image with random counter init vector"""
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    user_key = "E39FD7AB61AE6DDDA37158A0FC3008C6D61100A03C7516EA1BE55A39F546BAD5"
    key_store = KeyStore(KeySourceType.KEYSTORE, None)
    cert_block = certificate_block(data_dir, ["selfsign_2048_v3.der.crt"])
    priv_key_pem_data = _load_private_key(data_dir, "selfsign_privatekey_rsa2048.pem")
    mbi = MasterBootImage(
        app=org_data,
        image_type=MasterBootImageType.ENCRYPTED_RAM_IMAGE,
        load_addr=0x12345678,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
        hmac_key=user_key,
        key_store=key_store,
    )
    assert mbi.export()
    assert mbi.info()


@pytest.mark.parametrize(
    "der_certificates,root_index,expected_mbi",
    [
        # 3 certificates
        (
            ["selfsign_4096_v3.der.crt", "selfsign_3072_v3.der.crt", "selfsign_2048_v3.der.crt"],
            2,
            "evkmimxrt685_testfffffff_xip_3_certs_no_tz_mbi.bin",
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
            "evkmimxrt685_testfffffff_xip_4_certs_no_tz_mbi.bin",
        ),
        # 2 certificates (first and last)
        (
            ["selfsign_4096_v3.der.crt", None, None, "selfsign_2048_v3.der.crt"],
            3,
            "evkmimxrt685_testfffffff_xip_2_certs_no_tz_mbi.bin",
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
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, der_certificates, root_index)
    priv_key_pem_data = _load_private_key(data_dir, "selfsign_privatekey_rsa2048.pem")

    mbi = MasterBootImage(
        app=org_data,
        load_addr=0,
        image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
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
    with pytest.raises(ValueError):
        certificate_block(data_dir, der_file_names, 1)

    # public key in certificate and private key does not match
    der_file_names = ["selfsign_4096_v3.der.crt"]
    cert_block = certificate_block(data_dir, der_file_names, 0)
    priv_key_pem_data = _load_private_key(data_dir, "selfsign_privatekey_rsa2048.pem")
    with pytest.raises(ValueError):
        MasterBootImage(
            app=bytes(range(128)),
            load_addr=0,
            image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
            trust_zone=TrustZone.disabled(),
            cert_block=cert_block,
            priv_key_pem_data=priv_key_pem_data,
        ).export()

    # chain of certificates does not match
    der_file_names = ["selfsign_4096_v3.der.crt"]
    chain_certificates = ["ch3_crt2_v3.der.crt"]
    with pytest.raises(ValueError):
        certificate_block(data_dir, der_file_names, 0, chain_certificates)


@pytest.mark.parametrize(
    "der_certificates,chain_certificates,priv_key,expected_mbi",
    [
        # 2 certificates in chain
        (
            ["ca0_v3.der.crt"],
            ["crt_v3.der.crt"],
            "crt_privatekey_rsa2048.pem",
            "evkmimxrt685_testfffffff_xip_chain_2_no_tz_mbi.bin",
        ),
        # 3 certificates in chain
        (
            ["ca0_v3.der.crt"],
            ["ch3_crt_v3.der.crt", "ch3_crt2_v3.der.crt"],
            "crt2_privatekey_rsa2048.pem",
            "evkmimxrt685_testfffffff_xip_chain_3_no_tz_mbi.bin",
        ),
    ],
)
def test_signed_xip_certificates_chain_no_tz(
    data_dir, der_certificates, chain_certificates, priv_key, expected_mbi
):
    """Test signed image with multiple certificates, different key length
    :param data_dir: absolute path, where test data are located
    :param der_certificates: list of filenames of der root certificates
    :param chain_certificates: list of filenames of der cerificates
    :param priv_key: private key filename
    :param expected_mbi: filename of expected bootable image
    """
    with open(os.path.join(data_dir, "testfffffff.bin"), "rb") as f:
        org_data = f.read()
    # create certification block
    cert_block = certificate_block(data_dir, der_certificates, 0, chain_certificates)
    priv_key_pem_data = _load_private_key(data_dir, priv_key)

    mbi = MasterBootImage(
        app=org_data,
        load_addr=0,
        image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
        trust_zone=TrustZone.disabled(),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
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

    mbi = MasterBootImage(
        app=org_data,
        load_addr=0,
        image_type=MasterBootImageType.CRC_XIP_IMAGE,
        trust_zone=TrustZone.enabled(),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "input_img,load_addr,expected_mbi",
    [
        (
            "evkmimxrt595_hello_world_ram.bin",
            0x20080000,
            "evkmimxrt595_hello_world_ram_crc_default_tz_mbi.bin",
        ),
    ],
)
def test_plain_ram_crc_default_tz(data_dir, input_img, load_addr, expected_mbi):
    """Test plain image with CRC and default TZ-M
    :param data_dir: absolute path, where test data are located
    :param input_img: file name of input image (binary)
    :param load_addr: address where the image is loaded
    :param expected_mbi: file name of MBI image file with expected data
    """
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()

    mbi = MasterBootImage(
        app=org_data,
        load_addr=load_addr,
        image_type=MasterBootImageType.CRC_RAM_IMAGE,
        trust_zone=TrustZone.enabled(),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


@pytest.mark.parametrize(
    "input_img,tz_config,family,expected_mbi",
    [
        (
            "lpcxpresso55s69_led_blinky.bin",
            "lpc55xxA1.json",
            "lpc55xx",
            "lpc55_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt685_hello_world.bin",
            "rt6xx_test.json",
            "rt6xx",
            "evkmimxrt685_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt595_hello_world.bin",
            "rt5xxA0.json",
            "rt5xx",
            "evkmimxrt595_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt595_hello_world.bin",
            "rt5xx_empty.json",
            "rt5xx",
            "evkmimxrt595_hello_world_xip_crc_custom_tz_mbi.bin",
        ),
        (
            "evkmimxrt595_hello_world.bin",
            "rt5xx_few.json",
            "rt5xx",
            "evkmimxrt595_hello_world_xip_crc_custom_tz_mbi.bin",
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
    with open(os.path.join(data_dir, input_img), "rb") as f:
        org_data = f.read()
    with open(os.path.join(data_dir, expected_mbi), "rb") as f:
        expected_data = f.read()
    with open(os.path.join(data_dir, tz_config)) as f:
        tz_presets = json.load(f)["trustZonePreset"]

    mbi = MasterBootImage(
        app=org_data,
        load_addr=0,
        image_type=MasterBootImageType.CRC_XIP_IMAGE,
        trust_zone=TrustZone(family=family, customizations=tz_presets),
    )

    assert _compare_image(mbi, data_dir, expected_mbi)


def test_base_info(data_dir):
    """Basic test for MasterBootImage - information """
    # plain image
    mbi = MasterBootImage(app=bytes(range(64)), load_addr=0, enable_hw_user_mode_keys=True)
    output = mbi.info()
    repr_strings = [
        "Master Boot Image",
        "Image type",
        "Image length",
        "TrustZone",
        "HW user mode keys",
    ]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
    # CRC image
    mbi = MasterBootImage(
        app=bytes(range(64)), image_type=MasterBootImageType.CRC_RAM_IMAGE, load_addr=0x1000
    )
    output = mbi.info()
    repr_strings = ["Master Boot Image", "Image type", "Image length", "TrustZone"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
    # signed image
    priv_key_pem_data = _load_private_key(data_dir, "private_rsa4096.pem")
    cert_block = certificate_block(
        data_dir, ["selfsign_4096_v3.der.crt", "selfsign_3072_v3.der.crt"], 0
    )
    mbi = MasterBootImage(
        app=bytes(range(64)),
        load_addr=0x12345678,
        image_type=MasterBootImageType.SIGNED_XIP_IMAGE,
        trust_zone=TrustZone.custom("lpc55xx", {"MPU Control Register.(cm33_mpu_ctrl)": "0x0"}),
        cert_block=cert_block,
        priv_key_pem_data=priv_key_pem_data,
    )
    output = mbi.info()
    repr_strings = ["Master Boot Image", "Image type", "Image length", "TrustZone"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_multiple_images_with_relocation_table(data_dir):
    """Test image that contains multiple binary images and relocation table
    :param data_dir: absolute path, where test data are located
    """
    with open(os.path.join(data_dir, "multicore", "testfffffff.bin"), "rb") as f:
        img_data = f.read()
    with open(os.path.join(data_dir, "multicore", "normal_boot.bin"), "rb") as f:
        img1_data = f.read()
    with open(os.path.join(data_dir, "multicore", "special_boot.bin"), "rb") as f:
        img2_data = f.read()

    with open(os.path.join(data_dir, "multicore", "rt5xxA0.json"), "rb") as f:
        trust_zone_data = json.loads(f.read())["trustZonePreset"]

    table = MultipleImageTable()
    table.add_entry(MultipleImageEntry(img1_data, 0x80000))
    table.add_entry(MultipleImageEntry(img2_data, 0x80600))

    mbi = MasterBootImage(
        app=img_data,
        app_table=table,
        load_addr=0,
        image_type=MasterBootImageType.CRC_RAM_IMAGE,
        trust_zone=TrustZone.custom("rt5xx", trust_zone_data),
    )

    assert _compare_image(mbi, os.path.join(data_dir, "multicore"), "expected_output.bin")
