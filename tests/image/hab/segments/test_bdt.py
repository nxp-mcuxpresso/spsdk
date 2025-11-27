#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB Boot Data Table (BDT) segment tests.

This module contains unit tests for the HAB Boot Data Table segment functionality,
including export/parse operations, object equality and representation, information
display, and error handling for invalid plugin scenarios.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.segments.seg_bdt import SegBDT
from spsdk.image.hab.segments.seg_ivt import SegIVT


def test_bdt_export_parse() -> None:
    """Test BDT segment export and parse functionality.

    Verifies that a SegBDT object can be exported to binary data and then
    parsed back to create an equivalent object. Tests both default values
    and custom values for all BDT properties.

    :raises AssertionError: If the parsed BDT object doesn't match the original.
    """
    bdt = SegBDT()
    assert bdt.app_start == 0
    assert bdt.app_length == 0
    assert bdt.plugin == 0
    assert bdt.padding == 0

    # set nonzero values
    bdt.app_start = 0x8000000
    bdt.app_length = 1024
    bdt.plugin = 1

    data = bdt.export()
    bdt_parsed = SegBDT.parse(data)
    assert bdt == bdt_parsed


def test_bdt_eq_repr() -> None:
    """Test BDT segment equality and string representation functionality.

    Validates that the SegBDT class properly implements equality comparison
    and string representation methods. Tests that the repr output contains
    required strings and that different BDT instances or different segment
    types are not equal.
    """
    bdt = SegBDT()
    bdt_other = SegBDT(0x555)
    ivt2 = SegIVT(0x41)

    output = repr(bdt)
    repr_strings = ["BDT", "LEN", "Plugin:"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"

    assert bdt != bdt_other
    assert bdt != ivt2


def test_bdt_info() -> None:
    """Test BDT segment string representation functionality.

    Validates that SegBDT objects correctly display their configuration information
    in string format, including application start address, length, and plugin flag.
    Tests with different app_length values to ensure proper formatting across
    various data sizes.
    """
    bdt = SegBDT()

    # set nonzero values
    bdt.app_start = 0x8000000
    bdt.app_length = 40
    bdt.plugin = 1

    output = str(bdt)
    info_strings = ["Start", "App Length", "Plugin"]
    for info_string in info_strings:
        assert info_string in output, f"string {info_string} is not in the output: {output}"

    bdt1 = SegBDT()
    # set nonzero values
    bdt1.app_start = 0x8000000
    bdt1.app_length = 40777777
    bdt1.plugin = 1

    output = str(bdt1)
    info_strings = ["Start", "App Length", "Plugin"]
    for info_string in info_strings:
        assert info_string in output, f"string {info_string} is not in the output: {output}"


def test_bdt_invalid_plugin() -> None:
    """Test that BDT segment raises error for invalid plugin values.

    Validates that setting a plugin value outside the valid range (0-2)
    raises an SPSDKError with appropriate error message.

    :raises SPSDKError: When plugin value is outside valid range 0-2.
    """
    bdt = SegBDT()
    with pytest.raises(SPSDKError, match="Plugin value must be 0 .. 2"):
        bdt.plugin = 10
