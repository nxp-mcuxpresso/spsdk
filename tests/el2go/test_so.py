#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EL2GO Secure Objects test module.

This module contains comprehensive unit tests for the EL2GO secure objects functionality,
covering TLV element operations, secure object parsing, and validation mechanisms.
"""

import pytest

from spsdk.el2go.secure_objects import ElementTag, SecureObject, SecureObjects, TLVElement
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import load_binary


def test_tlvelement_parse_length() -> None:
    """Test TLVElement parse_length method functionality.

    This test verifies that the TLVElement.parse_length method correctly parses
    TLV (Tag-Length-Value) length fields from byte data according to the standard
    encoding rules. It tests various length encodings including short form (1 byte)
    and long form (multi-byte) representations.
    """
    assert TLVElement.parse_length(b"\x40\x01") == (1, 2)
    assert TLVElement.parse_length(b"\x40\x7f") == (0x7F, 2)
    assert TLVElement.parse_length(b"\x40\x81\xab") == (0xAB, 3)
    assert TLVElement.parse_length(b"\x40\x82\x01\x00") == (0x100, 4)
    assert TLVElement.parse_length(b"\x40\x83\x01\x00\x00") == (0x10000, 5)


def test_tlvelement_encode_length() -> None:
    """Test TLVElement encode_length method with various length values.

    This test verifies that the TLVElement.encode_length() method correctly encodes
    different length values according to the TLV (Tag-Length-Value) encoding rules:
    - Lengths 0-127 are encoded as single byte
    - Lengths 128-255 require length-of-length prefix
    - Larger lengths use multi-byte encoding with appropriate prefixes
    """
    assert TLVElement.encode_length(0x7F) == b"\x7f"
    assert TLVElement.encode_length(0x80) == b"\x81\x80"
    assert TLVElement.encode_length(0x100) == b"\x82\x01\x00"
    assert TLVElement.encode_length(0x10000) == b"\x83\x01\x00\x00"


def test_parse_single_object(data_dir: str) -> None:
    """Test parsing of a single secure object from binary data.

    Loads binary data from a test file and verifies that the SecureObject.parse()
    method correctly parses the data structure, checking the total length and
    the first and last element tags.

    :param data_dir: Directory path containing test data files.
    """
    data = load_binary(data_dir + "/full_data.bin")
    obj, _ = SecureObject.parse(data)
    assert obj.length == 14
    assert obj.size == 129
    assert obj[0].tag == ElementTag.MAGIC
    assert obj[-1].tag == ElementTag.SIGNATURE


def test_parse_whole(data_dir: str) -> None:
    """Test parsing of complete secure objects binary data.

    Verifies that SecureObjects.parse can correctly parse a full binary file
    containing multiple secure objects and validates the expected count and
    structure of the parsed objects.

    :param data_dir: Directory path containing test data files
    :raises AssertionError: If parsed objects don't match expected structure
    """
    objs = SecureObjects.parse(load_binary(data_dir + "/full_data.bin"))
    assert objs.length == 3
    assert objs[0].length == 14


def test_validator_ok(data_dir: str) -> None:
    """Test validator functionality with valid configurations.

    This test verifies that the SecureObjects validator system works correctly
    with both max_count and none validator configurations. It parses binary data
    and runs validators to ensure proper validation behavior.

    :param data_dir: Directory path containing test data files including full_data.bin
    """
    objs = SecureObjects.parse(load_binary(data_dir + "/full_data.bin"))
    validators = SecureObjects._make_validator("max_count=3")
    assert objs._run_validators(validators=validators)

    validators = SecureObjects._make_validator("none")
    assert objs._run_validators(validators=validators)


def test_validator_fail(data_dir: str) -> None:
    """Test that validator fails when maximum count constraint is violated.

    This test verifies that the SecureObjects validation system properly raises
    an SPSDKError when the number of objects exceeds the specified maximum count
    limit set by the validator.

    :param data_dir: Directory path containing test data files
    :raises SPSDKError: When the validator constraint is violated (expected behavior)
    """
    objs = SecureObjects.parse(load_binary(data_dir + "/full_data.bin"))
    validators = SecureObjects._make_validator("max_count=2")
    with pytest.raises(SPSDKError):
        objs._run_validators(validators=validators)


def test_validator_fail2() -> None:
    """Test SecureObjects validator failure scenarios.

    Tests multiple validation failure cases including maximum count validation,
    maximum secure object size validation, and maximum total size validation.
    Verifies that appropriate SPSDKError exceptions are raised with correct
    error messages for each validation constraint violation.

    :raises SPSDKError: When validation constraints are violated (expected behavior).
    """
    so = SecureObject()
    so.append(TLVElement(ElementTag.MAGIC, b"edgelock2go"))
    so.append(TLVElement(ElementTag.KEY_BLOB, bytes(1024)))
    so.append(TLVElement(ElementTag.SIGNATURE, bytes(1024)))

    objs = SecureObjects([so for _ in range(20)])

    validators = SecureObjects._make_validator("max_count=16")
    with pytest.raises(SPSDKError, match="Too many"):
        objs._run_validators(validators=validators)

    validators = SecureObjects._make_validator("max_so_size=1024;max_count=16")
    with pytest.raises(SPSDKError, match="too big"):
        objs._run_validators(validators=validators)

    validators = SecureObjects._make_validator("max_total_size=16384;max_so_size=1024;max_count=16")
    with pytest.raises(SPSDKError, match="Total size"):
        objs._run_validators(validators=validators)
