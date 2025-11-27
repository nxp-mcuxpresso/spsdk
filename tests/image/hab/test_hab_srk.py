#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB SRK table testing module.

This module contains comprehensive tests for HAB (High Assurance Boot) SRK
(Super Root Key) table functionality, including parsing, validation, and
export operations for both RSA and ECC certificates.
"""

import os
from typing import Any

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


def test_rsa_srk_table_parser(data_dir: str) -> None:
    """Test RSA SRK table parsing functionality.

    Validates that an RSA SRK table can be correctly parsed from binary data,
    verifying the table length, size, and fuse export functionality against
    expected reference data.

    :param data_dir: Directory path containing test data files including SRK table and fuse binaries.
    :raises AssertionError: When parsed SRK table properties don't match expected values.
    """
    with open(os.path.join(data_dir, "SRK_1_2_3_4_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 2112

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


def test_hashed_srk_table_parser(data_dir: str) -> None:
    """Test parsing of hashed SRK table from binary file.

    This test verifies that the SrkTable parser correctly reads a binary file
    containing a hashed SRK table with 4 entries, validates the table size,
    and ensures the exported fuses match the expected reference data.

    :param data_dir: Directory path containing test data files including
                     SRK_1_2_H3_H4_table.bin and SRK_1_2_3_4_fuse.bin
    """
    with open(os.path.join(data_dir, "SRK_1_2_H3_H4_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 1130

    with open(os.path.join(data_dir, "SRK_1_2_3_4_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


def test_srk_table_export(data_dir: str, test_certificates: Any) -> None:
    """Test SRK table export functionality.

    This test verifies that an SRK table can be created from certificates,
    exported to binary format, and parsed back correctly. It validates the
    round-trip conversion by comparing the exported data with reference data
    and ensuring the parsed table matches the original.

    :param data_dir: Directory path containing test data files.
    :param test_certificates: Collection of test certificates to create SRK items from.
    """
    srk_table = SrkTable(version=0x40)

    for test_cert in test_certificates:
        srk_table.append(SrkItem.from_certificate(test_cert))

    with open(os.path.join(data_dir, "SRK_1_2_3_4_table.bin"), "rb") as f:
        srk_table_data = f.read()

    assert srk_table.export() == srk_table_data
    assert srk_table == SrkTable.parse(srk_table_data)


def test_srk_table_single_cert(test_certificates: Any) -> None:
    """Test SrkTable functionality with a single certificate.

    Validates that SrkTable can be created with a single certificate and that all
    basic operations work correctly including export, fuse operations, and string
    representation.

    :param test_certificates: List of test certificates to use for testing.
    :raises SPSDKError: When accessing invalid fuse index (>= 8).
    """
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


def test_srk_table_cert_hashing(data_dir: str, test_certificates: Any) -> None:
    """Test SRK table creation with mixed certificate and hashed entries.

    This test recreates the SRK_1_2_H3_H4 table by combining regular certificate entries
    (items 1 and 2) with hashed certificate entries (items 3 and 4). It validates the
    table export functionality, fuse generation, and binary compatibility with reference data.

    :param data_dir: Path to directory containing test reference data files.
    :param test_certificates: List of test certificates to use for SRK table creation.
    """
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


def test_prime256v1_srk_table_parser(data_dir: str) -> None:
    """Test parsing of prime256v1 SRK table from binary file.

    This test verifies that a prime256v1 SRK table can be correctly parsed from a binary file,
    validates the table properties (length and size), and ensures that the exported fuses
    match the expected fuse data from a reference file.

    :param data_dir: Directory path containing test data files including SRK table and fuse binaries.
    """
    with open(os.path.join(data_dir, "SRK_prime256v1_table.bin"), "rb") as f:
        srk_table = SrkTable.parse(f.read())

    assert len(srk_table) == 4
    assert srk_table.size == 308

    with open(os.path.join(data_dir, "SRK_prime256v1_fuse.bin"), "rb") as f:
        srk_fuses = f.read()

    assert srk_table.export_fuses() == srk_fuses


def test_srktable_parse_not_valid_header() -> None:
    """Test SRK table parsing with invalid header tag.

    This test verifies that parsing an SRK item with an invalid header tag
    (0xFF) raises the appropriate NotImplementedSRKItem exception. It creates
    an RSA SRK item, corrupts its header tag, exports it, and then attempts
    to parse the corrupted data.

    :raises NotImplementedSRKItem: When attempting to parse SRK item with invalid header tag.
    """
    srkitem_rsa = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    srkitem_rsa._header._tag = 0xFF

    srkitem_rsa_out = srkitem_rsa.export()
    with pytest.raises(NotImplementedSRKItem):
        SrkItem.parse(srkitem_rsa_out)


def test_srktable_from_certificate_ecc(data_dir: str) -> None:
    """Test SRK table creation from ECC certificate.

    This test verifies that an SRK item can be correctly created from an ECC certificate,
    ensuring proper type instantiation, key size detection, and algorithm parameter setting.

    :param data_dir: Directory path containing test certificate files
    :raises AssertionError: If SRK item creation or validation fails
    """
    certificate = Certificate.load(os.path.join(data_dir, "ecc.crt"))
    srk = SrkItem.from_certificate(certificate)
    assert isinstance(srk, SrkItemEcc)
    assert srk.key_size == 256
    assert srk._header.param == EnumAlgorithm.ECDSA


def test_srkitemhash_parse_not_valid_header() -> None:
    """Test SrkItemHash parsing with invalid header parameter.

    This test verifies that parsing an SrkItemHash with an invalid header parameter
    (0x88) raises the expected NotImplementedSRKItem exception. The test creates a
    valid SrkItemHash, corrupts its header parameter, exports it, and then attempts
    to parse the corrupted data.

    :raises NotImplementedSRKItem: When parsing SrkItemHash with invalid header parameter.
    """
    srkhash = SrkItemHash(algorithm=0x17, digest=bytes(0x10))
    srkhash._header.param = 0x88
    srkhash_out = srkhash.export()
    with pytest.raises(NotImplementedSRKItem):
        SrkItemHash.parse(srkhash_out)


def test_srkitemhash_invalid_algorithm() -> None:
    """Test SrkItemHash with invalid algorithm parameter.

    Verifies that SrkItemHash constructor raises SPSDKError when provided
    with an invalid algorithm value that is not supported.

    :raises SPSDKError: When algorithm parameter is invalid (not a supported algorithm).
    """
    with pytest.raises(SPSDKError, match="Incorrect algorithm"):
        SrkItemHash(algorithm=88, digest=bytes(16))


def test_srktable_rsa_invalid_flag() -> None:
    """Test that SrkItemRSA raises error when setting invalid flag value.

    Verifies that attempting to set an invalid flag value (8) on an SrkItemRSA
    instance raises SPSDKError with appropriate error message.

    :raises SPSDKError: When invalid flag value is set on SrkItemRSA instance.
    """
    srk = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    with pytest.raises(SPSDKError, match="Incorrect flag"):
        srk.flag = 8


def test_srktable_ecc_invalid_flag() -> None:
    """Test SRK table ECC item with invalid flag value.

    This test verifies that setting an invalid flag value (8) on an ECC SRK item
    raises the appropriate SPSDKError with the expected error message.

    :raises SPSDKError: When an invalid flag value is set on the SRK item.
    """
    srk = SrkItemEcc(
        384,
        3665622270866885529978158465680747282513354288811938395515801825160156741722916065426997878229428508386024599713087,
        27083679052031733430535650892058391967780814535261890605452924654747789555719343684370905883997273475908096732191742,
    )
    with pytest.raises(SPSDKError, match="Incorrect flag"):
        srk.flag = 8


def test_srktable_export_parse_ecc(data_dir: str) -> None:
    """Test SRK table export and parse functionality for ECC certificates.

    This test verifies that an ECC certificate can be converted to an SRK item,
    exported to binary data, parsed back from that data, and the resulting
    SRK item matches the original.

    :param data_dir: Directory path containing test certificate files.
    :raises AssertionError: When parsed SRK item doesn't match the original.
    """
    certificate = Certificate.load(os.path.join(data_dir, "ecc.crt"))
    srk = SrkItemEcc.from_certificate(certificate)
    srk_data = srk.export()
    srk1 = SrkItemEcc.parse(srk_data)
    assert srk == srk1


def test_srk_table_invalid_fuse() -> None:
    """Test SRK table with invalid fuse index.

    Verifies that SrkTable.get_fuse() raises SPSDKError when called with
    an invalid fuse index (9) that is out of the valid range.

    :raises SPSDKError: When fuse index is out of valid range.
    """
    srk_table = SrkTable(version=0x40)
    with pytest.raises(SPSDKError, match="Incorrect index of the fuse"):
        srk_table.get_fuse(index=9)


def test_srk_table_item_not_eq() -> None:
    """Test that SrkItemRSA and SrkTable objects are not equal.

    This test verifies that inequality comparison works correctly between
    different HAB (High Assurance Boot) object types - specifically between
    an SRK (Super Root Key) item and an SRK table.
    """
    srk_table = SrkTable(version=0x40)
    srk = SrkItemRSA(modulus=bytes(2048), exponent=bytes(4))
    assert srk != srk_table
