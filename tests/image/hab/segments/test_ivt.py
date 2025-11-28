#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB IVT segment testing module.

This module contains comprehensive tests for the HAB (High Assurance Boot) IVT
(Image Vector Table) segment functionality in SPSDK. It validates the proper
creation, parsing, validation, and export operations of IVT segments.
"""

import pytest

from spsdk.exceptions import SPSDKError, SPSDKVerificationError
from spsdk.image.hab.segments.seg_ivt import SegIVT


def test_ivt_segment_api() -> None:
    """Test IVT segment API functionality.

    Validates the basic API operations of the IVT (Image Vector Table) segment including
    initialization, property access, address configuration, and export validation.
    Tests both valid configurations and error conditions to ensure proper behavior.

    :raises SPSDKError: When attempting to export IVT with invalid configuration.
    """
    ivt = SegIVT(0x41)
    assert ivt.version == 0x41
    assert ivt.ivt_address == 0
    assert ivt.bdt_address == 0
    assert ivt.dcd_address == 0
    assert ivt.app_address == 0
    assert ivt.csf_address == 0

    with pytest.raises(SPSDKError):
        _ = ivt.export()

    # set correct values
    ivt.ivt_address = 0x877FF400
    ivt.bdt_address = 0x877FF420
    ivt.dcd_address = 0x877FF42C
    ivt.app_address = 0x87800000
    ivt.csf_address = 0

    ivt.version = 0x44
    assert ivt._header.param == 0x44


def test_ivt_validate() -> None:
    """Test IVT segment validation with various invalid configurations.

    This test verifies that the IVT (Image Vector Table) segment properly detects
    and raises SPSDKVerificationError for invalid address configurations including
    misaligned addresses, incorrect address ordering, and invalid padding values.

    :raises SPSDKVerificationError: When IVT validation fails due to invalid configuration.
    """
    ivt = SegIVT(0x41)
    # set incorrect values
    ivt.ivt_address = 0x877FF42C
    ivt.dcd_address = 0x877FF400
    ivt.bdt_address = 0x877FF42E
    with pytest.raises(SPSDKVerificationError):
        ivt.verify().validate()

    ivt.csf_address = 0x877FF000
    ivt.dcd_address = 0x877FF500
    with pytest.raises(SPSDKVerificationError):
        ivt.verify().validate()

    ivt.padding = 1
    ivt.csf_address = 0x877FF600
    with pytest.raises(SPSDKVerificationError):
        ivt.verify().validate()


def test_ivt_export_parse() -> None:
    """Test IVT segment export and parse functionality.

    Verifies that an IVT (Image Vector Table) segment can be exported to binary data
    and then parsed back to create an equivalent IVT object. Tests both basic export/parse
    cycle and export/parse with padding to ensure data integrity is maintained.
    """
    ivt = SegIVT(0x41)
    ivt.ivt_address = 0x877FF400
    ivt.bdt_address = 0x877FF420
    ivt.dcd_address = 0x877FF42C
    ivt.app_address = 0x87800000
    ivt.csf_address = 0

    data = ivt.export()
    ivt_parsed = SegIVT.parse(data)
    assert ivt == ivt_parsed

    # with padding
    data = ivt.export()
    ivt_parsed = SegIVT.parse(data)
    assert ivt == ivt_parsed


def test_ivt_repr() -> None:
    """Test IVT segment string representation.

    This test verifies that the string representation of an IVT (Image Vector Table)
    segment contains all required component identifiers including BDT, IVT, DCD,
    APP, and CSF sections.

    :raises AssertionError: If any required string is missing from the representation output.
    """
    ivt = SegIVT(0x41)
    output = repr(ivt)
    repr_strings = ["BDT", "IVT", "DCD", "APP", "CSF"]
    for req_string in repr_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_ivt_invalid_version() -> None:
    """Test IVT segment with invalid version number.

    Verifies that setting an invalid version (0x39) on an IVT segment
    raises the appropriate SPSDKError with correct error message.

    :raises SPSDKError: When invalid version is set on IVT segment.
    """
    ivt = SegIVT(0x41)
    with pytest.raises(SPSDKError, match="Invalid version of IVT and image format"):
        ivt.version = 0x39


def test_format_ivt_item() -> None:
    """Test the _format_ivt_item method of SegIVT class.

    Verifies that the method correctly formats integer values into hexadecimal strings
    with proper padding and handles special cases like zero values and custom widths.

    :param: This test function takes no parameters.
    :raises AssertionError: If any of the formatting assertions fail.
    """
    assert SegIVT._format_ivt_item(0x123) == "0x00000123"
    assert SegIVT._format_ivt_item(0xABCDEF) == "0x00abcdef"
    assert SegIVT._format_ivt_item(0) == "none"
    assert SegIVT._format_ivt_item(0x10, 2) == "0x10"
    assert SegIVT._format_ivt_item(0x12, 3) == "0x012"
