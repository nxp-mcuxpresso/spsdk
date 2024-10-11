#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.signature_provider import get_signature_provider
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.crypto.cert_blocks import (
    CertBlock,
    CertBlockHeader,
    CertBlockV1,
    CertBlockV21,
    CertBlockVx,
    CertificateBlockHeader,
    IskCertificateLite,
    find_root_certificates,
)
from spsdk.utils.misc import load_binary


def test_cert_block_header():
    header = CertBlockHeader()
    assert header.version == "1.0"
    assert header.flags == 0
    assert header.build_number == 0
    assert header.image_length == 0
    assert header.cert_count == 0
    assert header.cert_table_length == 0

    data = header.export()
    assert len(data) == CertBlockHeader.SIZE

    header_parsed = CertBlockHeader.parse(data)
    assert header == header_parsed


def test_cert_block_header_invalid():
    with pytest.raises(SPSDKError, match="Invalid version"):
        CertBlockHeader(version="bbb")


def test_cert_block_basic():
    cb = CertBlockV1()
    # test default values
    assert cb.image_length == 0
    assert cb.alignment == 16
    assert cb.rkh_index is None
    # test setters
    cb.image_length = 1
    cb.alignment = 1
    assert cb.alignment == 1
    assert cb.image_length == 1
    assert cb.header.image_length == 1
    # invalid root key size
    with pytest.raises(SPSDKError):
        cb.set_root_key_hash(0, bytes())


def test_cert_block(data_dir):
    cert_obj = Certificate.load(os.path.join(data_dir, "selfsign_2048_v3.der.crt"))

    cb = CertBlockV1()
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    cb.add_certificate(cert_obj)
    assert cb.rkh_index == 0
    cb.export()

    # test RKHT
    assert cb.rkth.hex() == "db31d46c717711a8231cbc38b1de8a6e8657e1f733e04c2ee4b62fcea59149fa"
    fuses = cb.rkth_fuses
    assert len(fuses) == 8
    assert fuses[0] == 1825845723

    # test exception if child certificate in chain is not signed by parent certificate
    ca0_cert = Certificate.load(os.path.join(data_dir, "ca0_v3.der.crt"))
    with pytest.raises(SPSDKError):
        cb.add_certificate(ca0_cert)

    # test exception if no certificate specified
    cb = CertBlockV1()
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    with pytest.raises(SPSDKError):
        cb.export()

    # test exception last certificate is set as CA
    cb = CertBlockV1()
    cb.set_root_key_hash(0, ca0_cert.public_key_hash())
    cb.add_certificate(ca0_cert)
    with pytest.raises(SPSDKError):
        cb.export()

    # test exception if hash does not match any certificate
    cb = CertBlockV1()
    cb.set_root_key_hash(0, ca0_cert.public_key_hash())
    cb.add_certificate(cert_obj)
    with pytest.raises(SPSDKError):
        cb.export()


def test_add_invalid_cert_in_cert_block(data_dir):
    cb = CertBlockV1()
    with open(os.path.join(data_dir, "selfsign_2048_v3.der.crt"), "rb") as f:
        cert_data = f.read()
    with open(os.path.join(data_dir, "ca0_v3.der.crt"), "rb") as f:
        ca0_cert_data = f.read()
    with pytest.raises(SPSDKError):
        cb.add_certificate(cert=5)
    with pytest.raises(
        SPSDKError, match="Chain certificate cannot be verified using parent public key"
    ):
        cb.add_certificate(cert=cert_data)
        cb.add_certificate(cert=ca0_cert_data)


def test_cert_block_export_invalid(data_dir):
    cert_obj = Certificate.load(os.path.join(data_dir, "selfsign_2048_v3.der.crt"))
    cb = CertBlockV1()
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    cb.add_certificate(cert_obj)
    cb.add_certificate(cert_obj)
    assert cb.rkh_index == 0
    with pytest.raises(
        SPSDKError, match="All certificates except the last chain certificate must be CA"
    ):
        cb.export()


def test_invalid_cert_block_header():
    ch = CertificateBlockHeader()
    ch.MAGIC = b"chdx"
    data = ch.export()
    with pytest.raises(SPSDKError, match="Magic is not same!"):
        CertificateBlockHeader.parse(data=data)
    with pytest.raises(SPSDKError, match="SIZE is bigger than length of the data without offset"):
        CertificateBlockHeader.parse(data=bytes(8))


def test_cert_block_invalid():
    cb = CertBlockV1()
    with pytest.raises(SPSDKError, match="Invalid image length"):
        cb.image_length = -2
    with pytest.raises(SPSDKError, match="Invalid alignment"):
        cb.alignment = -2
    cb = CertBlockV1()
    with pytest.raises(SPSDKError, match="Invalid length of key hash"):
        cb.set_root_key_hash(0, bytes(5))


@pytest.mark.parametrize(
    "config,passed,expected_result",
    [
        ({}, False, SPSDKError),
        (
            {
                "mainCertPrivateKeyFile": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
            },
            True,
            0,
        ),
        (
            {
                "mainCertPrivateKeyFile": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "mainRootCertId": 1,
            },
            True,
            1,
        ),
        ({"mainRootCertId": 1}, True, 1),
        ({"mainCertChainId": 1}, True, 1),
        ({"mainRootCertId": "2"}, True, 2),
        ({"mainCertChainId": "2"}, True, 2),
        ({"mainRootCertId": "1abc"}, False, SPSDKValueError),
        ({"mainRootCertId": "1abc"}, False, SPSDKValueError),
        ({"mainRootCertId": 1, "mainCertChainId": 1}, True, 1),
        ({"mainRootCertId": 1, "mainCertChainId": 2}, False, SPSDKError),
    ],
)
def test_get_main_cert_index(data_dir, config, passed, expected_result):
    search_paths = [os.path.join(data_dir, "certs_and_keys")]
    if passed:
        result = CertBlockV1.get_main_cert_index(config, search_paths=search_paths)
        assert result == expected_result
    else:
        with pytest.raises(expected_result):
            CertBlockV1.get_main_cert_index(config, search_paths=search_paths)


@pytest.mark.parametrize(
    "config,index,cert_block_version",
    [
        (
            {
                "mainCertPrivateKeyFile": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k1_signed_cert0_noca.der.cert",
            },
            1,
            "cert_block_v1",
        ),
        (
            {
                "mainRootCertPrivateKeyFile": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k1_signed_cert0_noca.der.cert",
            },
            1,
            "cert_block_v21",
        ),
        (
            {
                "mainCertPrivateKeyFile": "k0_cert0_2048.pem",
                "rootCertificate0File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k1_signed_cert0_noca.der.cert",
            },
            None,
            "cert_block_v1",
        ),
        (
            {
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k2_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k3_signed_cert0_noca.der.cert",
            },
            None,
            "cert_block_v1",
        ),
        (
            {
                "mainCertPrivateKeyFile": "k0_cert0_2048.pem",
                "rootCertificate0File": "non_existing.cert",
                "rootCertificate1File": "another_non_existing.cert",
                "rootCertificate2File": "one_more_non_existing.cert",
            },
            None,
            "cert_block_v1",
        ),
        (
            {
                "mainCertPrivateKeyFile": "non_existing.pem",
                "rootCertificate0File": "root_k0_signed_cert0_noca.der.cert",
                "rootCertificate1File": "root_k1_signed_cert0_noca.der.cert",
                "rootCertificate2File": "root_k2_signed_cert0_noca.der.cert",
                "rootCertificate3File": "root_k3_signed_cert0_noca.der.cert",
            },
            None,
            "cert_block_v1",
        ),
    ],
)
def test_find_main_cert_index(data_dir, config, index, cert_block_version):
    cert_block_class: CertBlock = {"cert_block_v1": CertBlockV1, "cert_block_v21": CertBlockV21}[
        cert_block_version
    ]
    search_paths = [os.path.join(data_dir, "certs_and_keys")]
    found_index = cert_block_class.find_main_cert_index(config, search_paths=search_paths)
    assert found_index == index


@pytest.mark.parametrize(
    "config,error,expected_list",
    [
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
                "rootCertificate2File": "root_k2.cert",
                "rootCertificate3File": "root_k3.cert",
            },
            None,
            [
                "root_k0.cert",
                "root_k1.cert",
                "root_k2.cert",
                "root_k3.cert",
            ],
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
                "rootCertificate2File": "root_k2.cert",
                "rootCertificate3File": "",
            },
            None,
            [
                "root_k0.cert",
                "root_k1.cert",
                "root_k2.cert",
            ],
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
                "rootCertificate2File": "",
                "rootCertificate3File": "root_k2.cert",
            },
            SPSDKError,
            None,
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate3File": "root_k2.cert",
            },
            SPSDKError,
            None,
        ),
        (
            {
                "rootCertificate0File": "root_k0.cert",
                "rootCertificate1File": "root_k1.cert",
            },
            None,
            [
                "root_k0.cert",
                "root_k1.cert",
            ],
        ),
    ],
)
def test_find_root_certificates(config, error, expected_list):
    if error is not None:
        with pytest.raises(error):
            find_root_certificates(config)
    else:
        certificates = find_root_certificates(config)
        assert certificates == expected_list
        assert certificates == expected_list


def test_isk_cert_lite(data_dir):
    main_root_private_key_file = f"{data_dir}/ec_pk_secp256r1_cert0.pem"
    pub_key = f"{data_dir}/ec_secp256r1_cert0.pem"
    isk_cert = load_binary(pub_key)

    signature_provider = get_signature_provider(
        local_file_key=main_root_private_key_file,
    )

    cert = IskCertificateLite(isk_cert)
    cert.create_isk_signature(signature_provider)
    data = cert.export()
    assert data == IskCertificateLite.parse(data).export()


def test_cert_block_vx(data_dir):
    main_root_private_key_file = f"{data_dir}/ec_pk_secp256r1_cert0.pem"
    isk_certificate = f"{data_dir}/ec_secp256r1_cert0.pem"

    signature_provider = get_signature_provider(
        local_file_key=main_root_private_key_file,
    )
    isk_cert = load_binary(isk_certificate)

    cert_block = CertBlockVx(
        signature_provider=signature_provider,
        isk_cert=isk_cert,
        self_signed=True,
    )

    exported = cert_block.export()
    cert_block = CertBlockVx.parse(exported)
    cert_block.signature_provider = signature_provider
    assert len(cert_block.export()) == CertBlockVx.ISK_CERT_LENGTH


def test_cert_block_v31(data_dir):
    main_root_private_key_file = f"{data_dir}/ec_pk_secp256r1_cert0.pem"
    isk_certificate = f"{data_dir}/ec_secp256r1_cert0.pem"

    signature_provider = get_signature_provider(
        local_file_key=main_root_private_key_file,
    )
    isk_cert = load_binary(isk_certificate)

    rot = [load_binary(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem")) for x in range(4)]

    cert = CertBlockV21(
        root_certs=rot,
        signature_provider=signature_provider,
        isk_cert=isk_cert,
    )
    cert.calculate()
    exported = cert.export()
    CertBlockV21.parse(exported)
