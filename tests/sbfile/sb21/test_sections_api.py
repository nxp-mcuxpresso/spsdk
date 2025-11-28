#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2.1 sections API test module.

This module contains comprehensive tests for the SB2.1 (Secure Binary 2.1) file format
sections API functionality, including boot sections, certificate sections, and their
validation mechanisms. The tests cover section export, parsing, HMAC validation, header
validation, and error handling for malformed or invalid section data.
"""

import os

import pytest

from spsdk.crypto.certificate import Certificate
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.symmetric import Counter
from spsdk.exceptions import SPSDKError
from spsdk.image.cert_block.cert_blocks import CertBlockV1
from spsdk.sbfile.sb2.commands import CmdErase, CmdLoad, CmdReset
from spsdk.sbfile.sb2.sections import BootSectionV2, CertSectionV2
from spsdk.utils.family import FamilyRevision


def test_boot_section_v2() -> None:
    """Test BootSectionV2 functionality including creation, export, and parsing.

    Validates BootSectionV2 properties, data export with encryption parameters,
    successful parsing with valid parameters, and proper error handling for
    invalid parameter types and corrupted data.
    """
    boot_section = BootSectionV2(
        0, CmdErase(address=0, length=100000), CmdLoad(address=0, data=b"0123456789"), CmdReset()
    )

    assert boot_section.uid == 0
    assert not boot_section.is_last
    assert boot_section.hmac_count == 1
    assert boot_section.raw_size == 144

    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    data = boot_section.export(dek, mac, Counter(nonce))
    assert data
    assert BootSectionV2.parse(data, 0, False, dek, mac, Counter(nonce))

    with pytest.raises(SPSDKError, match="Invalid type of dek, should be bytes"):
        BootSectionV2.parse(
            data=data, offset=0, plain_sect=False, dek=4, mac=mac, counter=Counter(nonce)  # type: ignore
        )

    with pytest.raises(SPSDKError, match="Invalid type of mac, should be bytes"):
        BootSectionV2.parse(
            data=data, offset=0, plain_sect=False, dek=dek, mac=4, counter=Counter(nonce)  # type: ignore
        )

    with pytest.raises(SPSDKError, match="Invalid type of counter"):
        BootSectionV2.parse(data=data, offset=0, plain_sect=False, dek=dek, mac=mac, counter=5)  # type: ignore

    with pytest.raises(SPSDKError):
        assert BootSectionV2.parse(data, 0, False, dek, random_bytes(32), Counter(nonce))  # type: ignore


def test_boot_section_v2_invalid_export() -> None:
    """Test BootSectionV2 export method with invalid parameter types.

    This test verifies that the export method properly validates input parameter types
    and raises appropriate SPSDKError exceptions when invalid types are provided for
    dek, mac, and counter parameters.

    :raises SPSDKError: When dek parameter is not bytes type.
    :raises SPSDKError: When mac parameter is not bytes type.
    :raises SPSDKError: When counter parameter is not Counter type.
    """
    boot_section = BootSectionV2(
        0, CmdErase(address=0, length=100000), CmdLoad(address=0, data=b"0123456789"), CmdReset()
    )
    dek = 32
    mac = 4
    nonce = random_bytes(16)
    with pytest.raises(SPSDKError, match="Invalid type of dek, should be bytes"):
        boot_section.export(dek, mac, Counter(nonce))  # type: ignore
    dek = random_bytes(32)  # type: ignore
    with pytest.raises(SPSDKError, match="Invalid type of mac, should be bytes"):
        boot_section.export(dek, mac, Counter(nonce))  # type: ignore
    counter = 5  # type: ignore
    mac = random_bytes(32)  # type: ignore
    with pytest.raises(SPSDKError, match="Invalid type of counter"):
        boot_section.export(dek, mac, counter)  # type: ignore


def test_boot_section_v2_raw_size() -> None:
    """Test that BootSectionV2 calculates raw size correctly with custom HMAC size.

    This test verifies that when a BootSectionV2 instance is created with a specific
    UID and a custom HMAC_SIZE is set, the raw_size property returns the expected
    value of 32 bytes.
    """
    b_section = BootSectionV2(uid=2)
    b_section.HMAC_SIZE = 3
    assert b_section.raw_size == 32


def test_boot_section_v2_hmac_count() -> None:
    """Test BootSectionV2 HMAC count initialization.

    Verifies that a BootSectionV2 instance can be created with a specific
    UID and HMAC count, and that the UID property is correctly set.

    :raises AssertionError: If the UID is not set correctly.
    """
    b_section = BootSectionV2(uid=2, hmac_count=0)
    assert b_section.uid == 2


def _create_cert_block_v1(data_dir: str) -> CertBlockV1:
    """Create a certificate block v1 for testing purposes.

    This method creates a CertBlockV1 instance with Ambassador family revision,
    loads a self-signed certificate from the specified data directory, sets the
    root key hash, and adds the certificate to the block.

    :param data_dir: Directory path containing the certificate file.
    :raises SPSDKError: If certificate file cannot be loaded or processed.
    :return: Configured certificate block v1 instance.
    """
    cb = CertBlockV1(FamilyRevision("Ambassador"))
    cert_obj = Certificate.load(os.path.join(data_dir, "selfsign_v3.der.crt"))
    cb.set_root_key_hash(0, cert_obj.public_key_hash())
    cb.add_certificate(cert_obj)
    return cb


def test_certificate_section_v2(data_dir: str) -> None:
    """Test certificate section v2 functionality.

    Tests the CertSectionV2 class including initialization, export/parse operations,
    and error handling scenarios. Verifies that the section can be properly exported
    with encryption parameters and parsed back, while ensuring proper validation
    of MAC values.

    :param data_dir: Directory path containing test certificate data files.
    :raises AssertionError: When CertSectionV2 is initialized with None.
    :raises SPSDKError: When parsing fails due to invalid MAC value.
    """
    with pytest.raises(AssertionError):
        CertSectionV2(None)  # type: ignore

    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    data = cs.export(dek, mac, Counter(nonce))
    assert data
    assert CertSectionV2.parse(data, 0, dek, mac, Counter(nonce))

    with pytest.raises(SPSDKError):
        CertSectionV2.parse(data, 0, dek, random_bytes(32), Counter(nonce))  # type: ignore


def test_invalid_export_cert_section_v2(data_dir: str) -> None:
    """Test invalid export of certificate section v2 with incorrect HMAC size.

    This test verifies that exporting a CertSectionV2 with an invalid HMAC size
    raises the appropriate SPSDKError exception.

    :param data_dir: Directory path containing test data files for certificate creation.
    :raises SPSDKError: When HMAC size is invalid during export operation.
    """
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    dek = random_bytes(16)
    mac = random_bytes(16)
    nonce = random_bytes(16)
    cs.HMAC_SIZE = 137
    with pytest.raises(SPSDKError, match="Invalid size"):
        cs.export(dek, mac, Counter(nonce))  # type: ignore


def test_certificate_block_v2(data_dir: str) -> None:
    """Test certificate block version 2 functionality.

    Creates a certificate block version 1 for testing purposes and validates
    the certificate block v2 implementation against it.

    :param data_dir: Directory path containing test data files and certificates.
    """
    _create_cert_block_v1(data_dir)


def test_invalid_parse_cert_section_v2(data_dir: str) -> None:
    """Test invalid parsing of CertSectionV2 with incorrect parameter types.

    This test verifies that CertSectionV2.parse() properly raises SPSDKError
    when called with invalid parameter types for dek, mac, and counter arguments.

    :param data_dir: Directory path containing test data files.
    """
    with pytest.raises(SPSDKError):
        CertSectionV2.parse(bytes(123), 0, dek="6")  # type: ignore
    with pytest.raises(SPSDKError):
        CertSectionV2.parse(bytes(123), 0, mac="6")  # type: ignore
    with pytest.raises(SPSDKError):
        CertSectionV2.parse(bytes(123), 0, counter="6")  # type: ignore


def test_invalid_header_hmac(data_dir: str) -> None:
    """Test invalid header HMAC validation in certificate section parsing.

    This test verifies that CertSectionV2.parse() properly validates the HMAC
    in the header by corrupting the first 32 bytes (HMAC field) of valid
    certificate section data and ensuring an SPSDKError is raised.

    :param data_dir: Directory path containing test certificate data files.
    :raises SPSDKError: Expected exception when HMAC validation fails.
    """
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    invalid_data = valid_data
    invalid_data = bytearray(invalid_data)
    invalid_data[0:32] = bytearray(32)
    with pytest.raises(SPSDKError, match="HMAC"):
        CertSectionV2.parse(invalid_data, 0, dek, mac, Counter(nonce))  # type: ignore


def test_invalid_header_tag(data_dir: str) -> None:
    """Test invalid header tag in certificate section parsing.

    This test verifies that CertSectionV2.parse() properly validates the header tag
    and raises an appropriate error when an invalid tag is encountered during parsing.

    :param data_dir: Directory path containing test certificate data files
    :raises SPSDKError: When header tag validation fails during parsing
    """
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    cs._header.tag += 1
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    with pytest.raises(SPSDKError, match="TAG"):
        CertSectionV2.parse(data=valid_data, mac=mac, dek=dek, counter=Counter(nonce))  # type: ignore


def test_invalid_header_flag(data_dir: str) -> None:
    """Test invalid header flag in certificate section parsing.

    This test verifies that CertSectionV2.parse() properly validates header flags
    by modifying a valid certificate section's header flags and ensuring that
    parsing fails with an appropriate error message.

    :param data_dir: Directory path containing test data files for certificate creation.
    :raises SPSDKError: When header flags validation fails during parsing.
    """
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    cs._header.flags += 1
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    with pytest.raises(SPSDKError, match="FLAGS"):
        CertSectionV2.parse(data=valid_data, mac=mac, dek=dek, counter=Counter(nonce))  # type: ignore


def test_invalid_header_flag2(data_dir: str) -> None:
    """Test invalid header flag by modifying address field.

    This test verifies that CertSectionV2.parse() properly validates the header
    mark by detecting when the address field has been tampered with. It creates
    a valid certificate section, modifies the header address, exports the data,
    and then attempts to parse it back, expecting an SPSDKError related to the mark.

    :param data_dir: Directory path containing test data files
    :raises SPSDKError: When the header mark validation fails during parsing
    """
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    cs._header.address += 1
    dek = random_bytes(32)
    mac = random_bytes(32)
    nonce = random_bytes(16)
    valid_data = cs.export(dek, mac, Counter(nonce))
    with pytest.raises(SPSDKError, match="Mark"):
        CertSectionV2.parse(data=valid_data, mac=mac, dek=dek, counter=Counter(nonce))  # type: ignore


def test_cert_section(data_dir: str) -> None:
    """Test certificate section creation and representation.

    Validates that a CertSectionV2 object can be created from a certificate block
    and that its string representation matches the expected format with correct length.

    :param data_dir: Directory path containing test certificate data files.
    """
    cs = CertSectionV2(_create_cert_block_v1(data_dir))
    assert "CertSectionV2: Length=1296" == repr(cs)
