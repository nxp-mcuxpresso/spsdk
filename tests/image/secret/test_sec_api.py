#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from spsdk import SPSDKError
from spsdk.crypto.loaders import load_certificate
from spsdk.image import MAC, CertificateImg, SecretKeyBlob, Signature, SrkItem, SrkTable
from spsdk.image.commands import CmdNop
from spsdk.image.secret import (
    BaseClass,
    NotImplementedSRKCertificate,
    NotImplementedSRKItem,
    NotImplementedSRKPublicKeyType,
    SrkItemHash,
    SrkItemRSA,
)


@pytest.fixture(scope="module", name="srk_pem")
def srk_pem_func(data_dir):
    srk_pem = []
    for i in range(4):
        srk_pem_file = "SRK{}_sha256_4096_65537_v3_ca_crt.pem".format(i + 1)
        with open(os.path.join(data_dir, srk_pem_file), "rb") as f:
            srk_pem.append(f.read())
    return srk_pem


def test_rsa_srk_table_parser(data_dir):
    with open(os.path.join(data_dir, "SRK_1_2_3_4_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 2112

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


@pytest.mark.xfail(raises=NotImplementedSRKPublicKeyType)
def test_prime256v1_srk_table_parser(data_dir):
    "EC keys are not yet supported"
    with open(os.path.join(data_dir, "SRK_prime256v1_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 308

    with open(os.path.join(data_dir, "SRK_prime256v1_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


def test_hashed_srk_table_parser(data_dir):
    with open(os.path.join(data_dir, "SRK_1_2_H3_H4_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 1130

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


def test_srk_table_export(data_dir, srk_pem):
    srk_table = SrkTable(version=0x40)

    for pem_data in srk_pem:
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        srk_table.append(SrkItem.from_certificate(cert))

    with open(os.path.join(data_dir, "SRK_1_2_3_4_table.bin"), "rb") as f:
        srk_table_data = f.read()

    assert srk_table.export() == srk_table_data
    assert srk_table == SrkTable.parse(srk_table_data)


def test_srk_table_single_cert(srk_pem):
    """Smoke test that SrkTable with single certificate works"""
    srk_table = SrkTable(version=0x40)
    cert = x509.load_pem_x509_certificate(srk_pem[0], default_backend())
    srk_table.append(SrkItem.from_certificate(cert))

    # test export() returns any result
    assert srk_table.export()
    # test export_fuses() returns valid length
    assert len(srk_table.export_fuses()) == 32
    # test get_fuse() returns valid value
    for fuse_index in range(8):
        assert srk_table.get_fuse(fuse_index) >= 0
    with pytest.raises(SPSDKError):
        srk_table.get_fuse(8)
    # test info() returns non-empty text
    assert srk_table.info()  # test export returns any result


def test_srk_table_cert_hashing(data_dir, srk_pem):
    """Recreate SRK_1_2_H3_H4 table from certificates"""
    srk_table = SrkTable(version=0x40)
    srk_table.append(
        SrkItem.from_certificate(x509.load_pem_x509_certificate(srk_pem[0], default_backend()))
    )
    srk_table.append(
        SrkItem.from_certificate(x509.load_pem_x509_certificate(srk_pem[1], default_backend()))
    )
    srk_table.append(
        SrkItem.from_certificate(
            x509.load_pem_x509_certificate(srk_pem[2], default_backend())
        ).hashed_entry()
    )
    srk_table.append(
        SrkItem.from_certificate(
            x509.load_pem_x509_certificate(srk_pem[3], default_backend())
        ).hashed_entry()
    )
    assert srk_table.export()
    assert len(srk_table.export_fuses()) == 32
    assert srk_table.info()  # test export returns any result

    with open(os.path.join(data_dir, "SRK_1_2_H3_H4_table.bin"), "rb") as f:
        preimaged_srk_table_data = f.read()
    assert srk_table.export() == preimaged_srk_table_data
    assert srk_table == SrkTable.parse(preimaged_srk_table_data)

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
        srk_fuses = f.read()
    assert srk_table.export_fuses() == srk_fuses


def test_mac_class():
    mac = MAC(version=0x40)

    assert mac.size == 8 + 16
    assert mac.info()

    test_nonce = b"0123456789123"
    test_mac = b"fedcba9876543210"
    mac = MAC(version=0x42, nonce_len=13, mac_len=16, data=test_nonce + test_mac)
    assert mac.size == 8 + 13 + 16
    assert mac.data == test_nonce + test_mac
    assert mac.nonce == test_nonce
    assert mac.mac == test_mac
    mac.data = test_nonce + test_mac
    assert mac.data == test_nonce + test_mac
    assert mac.nonce == test_nonce
    assert mac.mac == test_mac

    with pytest.raises(SPSDKError):
        mac.data = test_mac


def test_mac_invalid():
    mac = MAC()
    with pytest.raises(SPSDKError, match="Incorrect length of mac"):
        mac.update_aead_encryption_params(mac=bytes(4), nonce=bytes(12))
    with pytest.raises(SPSDKError, match="Incorrect length of nonce"):
        mac.update_aead_encryption_params(mac=bytes(16), nonce=bytes(4))
    mac = MAC(mac_len=15)
    with pytest.raises(SPSDKError, match="Incorrect number of MAC bytes"):
        mac.update_aead_encryption_params(mac=bytes(16), nonce=bytes(12))


def test_signature_class():
    sig = Signature(version=0x40)

    assert sig.size == 4
    assert sig.info()


def test_certificate_class():
    cer = CertificateImg(version=0x40)

    assert cer.size == 4
    assert cer.info()


def test_secret_key_blob_class():
    sec_key = SecretKeyBlob(mode=0, algorithm=0, flag=0)
    sec_key.blob = bytes([0xFF] * 32)

    assert sec_key.size == 36
    assert sec_key.info()


def test_keyblob_base():
    sec_key = SecretKeyBlob(mode=0, algorithm=0, flag=0)
    assert "SecKeyBlob " in repr(sec_key)
    output = repr(sec_key)
    repr_strings = ["SecKeyBlob ", "Mode", "Algo", "Flag", "Size"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_keyblob_eq():
    sec_key = SecretKeyBlob(mode=0, algorithm=0, flag=0)
    sec_key_other = SecretKeyBlob(mode=0, algorithm=0, flag=0)
    sec_key_different = SecretKeyBlob(mode=0, algorithm=1, flag=0)
    assert sec_key == sec_key_other
    assert sec_key != sec_key_different


def test_keyblob_export_parse():
    tested_key = SecretKeyBlob(mode=0, algorithm=0, flag=0)
    packed_key = tested_key.export()
    unpacked = tested_key.parse(packed_key)
    assert unpacked == tested_key


def test_srktable_parse_not_valid_header():
    srkitem_rsa = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    srkitem_rsa._header._tag = 0xFF

    srkitem_rsa_out = srkitem_rsa.export()
    with pytest.raises(NotImplementedSRKItem):
        SrkItem.parse(srkitem_rsa_out)


def test_srktable_from_certificate_ecc(data_dir):
    certificate = load_certificate(os.path.join(data_dir, "ecc.crt"))

    with pytest.raises(NotImplementedSRKCertificate):
        SrkItem.from_certificate(certificate)


def test_srkitemhash_parse_not_valid_header():
    srkhash = SrkItemHash(algorithm=0x17, digest=bytes(0x10))
    srkhash._header.param = 0x88
    srkhash_out = srkhash.export()
    with pytest.raises(NotImplementedSRKItem):
        SrkItemHash.parse(srkhash_out)


def test_srkitemhash_invalid_algorithm():
    with pytest.raises(SPSDKError, match="Incorrect algorithm"):
        SrkItemHash(algorithm=88, digest=bytes(16))


def test_srktable_invalid_flag():
    srk = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    with pytest.raises(SPSDKError, match="Incorrect flag"):
        srk.flag = 8


def test_srk_table_invalid_fuse():
    srk_table = SrkTable(version=0x40)
    with pytest.raises(SPSDKError, match="Incorrect index of the fuse"):
        srk_table.get_fuse(index=9)


def test_srk_table_item_not_eq():
    srk_table = SrkTable(version=0x40)
    srk = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    assert srk != srk_table


def test_not_eq():
    cmd = BaseClass(tag=3)
    cmd2 = CmdNop()
    assert cmd != cmd2
