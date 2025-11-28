#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB header command unit tests.

This module contains comprehensive unit tests for HAB (High Assurance Boot) header
command functionality in SPSDK, covering header creation, parsing, serialization,
and error handling scenarios.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.hab_header import CmdHeader, Header, SegmentTag


def test_basic_header_without_length() -> None:
    """Test basic Header creation without specifying length parameter.

    Validates that a Header object can be created with only a tag parameter,
    and verifies that default values are properly set for param and length fields.
    Also tests the string representation methods to ensure proper formatting.

    :raises AssertionError: If any of the header properties don't match expected values.
    """
    tested_header = Header(SegmentTag.IVT.tag)
    assert tested_header.tag == SegmentTag.IVT
    assert tested_header.param == 0
    assert tested_header.length == tested_header.SIZE

    assert "Header" in repr(tested_header)
    output = str(tested_header)
    repr_strings = ["TAG", "PARAM", "LEN"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_basic_header_with_length() -> None:
    """Test basic header creation with specified length parameter.

    Verifies that a Header object can be created with a specific tag and length,
    and that all attributes are properly initialized with expected values.

    :raises AssertionError: If any of the header attributes don't match expected values.
    """
    tested_header = Header(SegmentTag.IVT.tag, length=10)
    assert tested_header.tag == SegmentTag.IVT
    assert tested_header.param == 0
    assert tested_header.length == 10


def test_unpacking_packing_header_without_length() -> None:
    """Test unpacking and packing of header without length field.

    Validates that a Header object with IVT segment tag can be properly exported
    to binary format and then parsed back to an equivalent Header object.

    :raises AssertionError: When the parsed header doesn't match the original header.
    """
    tested_header = Header(SegmentTag.IVT.tag)
    packed_header = tested_header.export()
    unpacked = tested_header.parse(packed_header)
    assert unpacked == tested_header


def test_unpacking_packing_header_with_length() -> None:
    """Test header packing and unpacking functionality with length parameter.

    Verifies that a Header object with a specified length can be properly
    exported to binary format and then parsed back to an equivalent object.
    The test ensures data integrity through the pack/unpack cycle.

    :raises AssertionError: If the unpacked header doesn't match the original header.
    """
    tested_header = Header(SegmentTag.IVT.tag, length=10)
    packed_header = tested_header.export()
    unpacked = tested_header.parse(packed_header)
    assert unpacked == tested_header


def test_parse_invalid_command() -> None:
    """Test parsing of invalid command headers.

    Validates that CmdHeader.parse properly raises SPSDKError when given
    invalid input data including invalid required_tag values, zero-length
    data, and invalid command tags.

    :raises SPSDKError: When parsing fails due to invalid input parameters or data.
    """
    # invalid required_tag: not CmdTag
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"", required_tag=-1)
    # invalid zero length
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"\xff\x00\x00\x00", required_tag=None)
    # invalid tag: not CmdTag
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"\xff\x04\x00\x00", required_tag=None)
