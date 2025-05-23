#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os

import pytest
from spsdk.crypto.certificate import Certificate
from spsdk.exceptions import SPSDKError
from spsdk.image.hab.constants import EnumAlgorithm
from spsdk.image.hab.hab_srk import (
    NotImplementedSRKItem,
    SrkItem,
    SrkItemEcc,
    SrkItemHash,
    SrkItemRSA,
    SrkTable,
)


def test_rsa_srk_table_parser(data_dir):
    with open(os.path.join(data_dir, "SRK_1_2_3_4_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 2112

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
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


def test_srk_table_export(data_dir, test_certificates):
    srk_table = SrkTable(version=0x40)

    for test_cert in test_certificates:
        srk_table.append(SrkItem.from_certificate(test_cert))

    with open(os.path.join(data_dir, "SRK_1_2_3_4_table.bin"), "rb") as f:
        srk_table_data = f.read()

    assert srk_table.export() == srk_table_data
    assert srk_table == SrkTable.parse(srk_table_data)


def test_srk_table_single_cert(test_certificates):
    """Smoke test that SrkTable with single certificate works"""
    srk_table = SrkTable(version=0x40)
    srk_table.append(SrkItem.from_certificate(test_certificates[0]))

    # test export() returns any result
    assert srk_table.export()
    # test export_fuses() returns valid length
    assert len(srk_table.export_fuses()) == 32
    # test get_fuse() returns valid value
    for fuse_index in range(8):
        assert srk_table.get_fuse(fuse_index) >= 0
    with pytest.raises(SPSDKError):
        srk_table.get_fuse(8)
    # test __str__() returns non-empty text
    assert str(srk_table)  # test export returns any result


def test_srk_table_cert_hashing(data_dir, test_certificates):
    """Recreate SRK_1_2_H3_H4 table from certificates"""
    srk_table = SrkTable(version=0x40)
    srk_table.append(SrkItem.from_certificate(test_certificates[0]))
    srk_table.append(SrkItem.from_certificate(test_certificates[1]))
    srk_table.append(SrkItem.from_certificate(test_certificates[2]).hashed_entry())
    srk_table.append(SrkItem.from_certificate(test_certificates[3]).hashed_entry())
    assert srk_table.export()
    assert len(srk_table.export_fuses()) == 32
    assert str(srk_table)  # test export returns any result

    with open(os.path.join(data_dir, "SRK_1_2_H3_H4_table.bin"), "rb") as f:
        preimaged_srk_table_data = f.read()
    assert srk_table.export() == preimaged_srk_table_data
    assert srk_table == SrkTable.parse(preimaged_srk_table_data)

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
        srk_fuses = f.read()
    assert srk_table.export_fuses() == srk_fuses


def test_prime256v1_srk_table_parser(data_dir):
    with open(os.path.join(data_dir, "SRK_prime256v1_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 308

    with open(os.path.join(data_dir, "SRK_prime256v1_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


def test_srktable_parse_not_valid_header():
    srkitem_rsa = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    srkitem_rsa._header._tag = 0xFF

    srkitem_rsa_out = srkitem_rsa.export()
    with pytest.raises(NotImplementedSRKItem):
        SrkItem.parse(srkitem_rsa_out)


def test_srktable_from_certificate_ecc(data_dir):
    certificate = Certificate.load(os.path.join(data_dir, "ecc.crt"))
    srk = SrkItem.from_certificate(certificate)
    assert isinstance(srk, SrkItemEcc)
    assert srk.key_size == 256
    assert srk._header.param == EnumAlgorithm.ECDSA


def test_srkitemhash_parse_not_valid_header():
    srkhash = SrkItemHash(algorithm=0x17, digest=bytes(0x10))
    srkhash._header.param = 0x88
    srkhash_out = srkhash.export()
    with pytest.raises(NotImplementedSRKItem):
        SrkItemHash.parse(srkhash_out)


def test_srkitemhash_invalid_algorithm():
    with pytest.raises(SPSDKError, match="Incorrect algorithm"):
        SrkItemHash(algorithm=88, digest=bytes(16))


def test_srktable_rsa_invalid_flag():
    srk = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    with pytest.raises(SPSDKError, match="Incorrect flag"):
        srk.flag = 8


def test_srktable_ecc_invalid_flag():
    srk = SrkItemEcc(
        384,
        3665622270866885529978158465680747282513354288811938395515801825160156741722916065426997878229428508386024599713087,
        27083679052031733430535650892058391967780814535261890605452924654747789555719343684370905883997273475908096732191742,
    )
    with pytest.raises(SPSDKError, match="Incorrect flag"):
        srk.flag = 8


def test_srktable_export_parse_ecc(data_dir):
    certificate = Certificate.load(os.path.join(data_dir, "ecc.crt"))
    srk = SrkItemEcc.from_certificate(certificate)
    srk_data = srk.export()
    srk1 = SrkItemEcc.parse(srk_data)
    assert srk == srk1


def test_srk_table_invalid_fuse():
    srk_table = SrkTable(version=0x40)
    with pytest.raises(SPSDKError, match="Incorrect index of the fuse"):
        srk_table.get_fuse(index=9)


def test_srk_table_item_not_eq():
    srk_table = SrkTable(version=0x40)
    srk = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    assert srk != srk_table
