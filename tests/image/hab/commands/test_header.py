#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.image.hab.hab_header import CmdHeader, Header
from spsdk.image.hab.hab_header import SegmentTag


def test_basic_header_without_length():
    """Basic test for header without length"""
    tested_header = Header(SegmentTag.IVT.tag)
    assert tested_header.tag == SegmentTag.IVT
    assert tested_header.param == 0
    assert tested_header.length == tested_header.SIZE

    assert "Header" in repr(tested_header)
    output = str(tested_header)
    repr_strings = ["TAG", "PARAM", "LEN"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_basic_header_with_length():
    """Basic Test for header with length"""
    tested_header = Header(SegmentTag.IVT.tag, length=10)
    assert tested_header.tag == SegmentTag.IVT
    assert tested_header.param == 0
    assert tested_header.length == 10


def test_unpacking_packing_header_without_length():
    """Test for header (without length) for packing and unpacking"""
    tested_header = Header(SegmentTag.IVT.tag)
    packed_header = tested_header.export()
    unpacked = tested_header.parse(packed_header)
    assert unpacked == tested_header


def test_unpacking_packing_header_with_length():
    """Test for header (with length) for packing and unpacking"""
    tested_header = Header(SegmentTag.IVT.tag, length=10)
    packed_header = tested_header.export()
    unpacked = tested_header.parse(packed_header)
    assert unpacked == tested_header


def test_parse_invalid_command():
    # invalid required_tag: not CmdTag
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"", required_tag=-1)
    # invalid zero length
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"\xff\x00\x00\x00", required_tag=None)
    # invalid tag: not CmdTag
    with pytest.raises(SPSDKError):
        CmdHeader.parse(b"\xff\x04\x00\x00", required_tag=None)
