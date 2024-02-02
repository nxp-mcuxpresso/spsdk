#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.header import CmdHeader, Header, Header2, SegTag


def test_basic_header_without_length():
    """Basic test for header without length"""
    tested_header = Header(SegTag.IVT2.tag)
    assert tested_header.tag == SegTag.IVT2
    assert tested_header.param == 0
    assert tested_header.length == tested_header.SIZE

    assert "Header" in repr(tested_header)
    output = str(tested_header)
    repr_strings = ["TAG", "PARAM", "LEN"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_basic_header_with_length():
    """Basic Test for header with length"""
    tested_header = Header(SegTag.IVT2.tag, length=10)
    assert tested_header.tag == SegTag.IVT2
    assert tested_header.param == 0
    assert tested_header.length == 10


def test_unpacking_packing_header_without_length():
    """Test for header (without length) for packing and unpacking"""
    tested_header = Header(SegTag.IVT2.tag)
    packed_header = tested_header.export()
    unpacked = tested_header.parse(packed_header)
    assert unpacked == tested_header


def test_unpacking_packing_header_with_length():
    """Test for header (with length) for packing and unpacking"""
    tested_header = Header(SegTag.IVT2.tag, length=10)
    packed_header = tested_header.export()
    unpacked = tested_header.parse(packed_header)
    assert unpacked == tested_header


def test_basic_header2_without_length():
    """Basic Test for header2 without length"""
    tested_header2 = Header2(SegTag.IVT2.tag)
    assert tested_header2.tag == SegTag.IVT2
    assert tested_header2.param == 0
    assert tested_header2.length == tested_header2.size


def test_basic_header2_with_length():
    """Basic Test for header2 with length"""
    tested_header2 = Header2(SegTag.IVT2.tag, length=20)
    assert tested_header2.tag == SegTag.IVT2
    assert tested_header2.param == 0
    assert tested_header2.length == 20


def test_unpacking_packing_header2_with_length():
    """Test for header2 (with length) for packing and unpacking"""
    tested_header2 = Header2(SegTag.IVT2.tag, length=20)
    packed_header2 = tested_header2.export()
    unpacked2 = tested_header2.parse(packed_header2)
    assert unpacked2 == tested_header2


def test_unpacking_header2_without_length():
    """Test for header for packing and unpacking"""
    tested_header2 = Header2(SegTag.IVT2.tag)
    packed_header2 = tested_header2.export()
    unpacked2 = tested_header2.parse(packed_header2)
    assert unpacked2 == tested_header2


def test_comparison_header_with_length():
    """Test for comparing header and header 2 (with length) for packing and unpacking"""
    tested_header2 = Header2(SegTag.IVT2.tag, length=20)
    tested_header = Header(SegTag.IVT2.tag, length=20)
    packed_header2 = tested_header2.export()
    packed_header = tested_header.export()
    unpacked2 = tested_header2.parse(packed_header2)
    unpacked = tested_header.parse(packed_header)
    assert unpacked2 != unpacked
    assert packed_header2 != packed_header


def test_comparison_header_without_length():
    """Test for comparing header and header 2 (without length) for packing and unpacking"""
    tested_header2 = Header2(SegTag.IVT2.tag)
    tested_header = Header(SegTag.IVT2.tag)
    packed_header2 = tested_header2.export()
    packed_header = tested_header.export()
    unpacked2 = tested_header2.parse(packed_header2)
    unpacked = tested_header.parse(packed_header)
    assert unpacked2 != unpacked
    assert packed_header2 != packed_header


def test_parse_invalid_command():
    # invalid required_tag: not CmdTag
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"", required_tag=-1)
    # invalid zero length
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"\xFF\x00\x00\x00", required_tag=None)
    # invalid tag: not CmdTag
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"\xFF\x04\x00\x00", required_tag=None)
