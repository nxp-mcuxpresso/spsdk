#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK HAB Check Data command functionality.

This module contains comprehensive unit tests for the CmdCheckData class
and CheckDataOpsEnum enumeration used in HAB (High Assurance Boot) image
processing within the SPSDK framework.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_check_data import CheckDataOpsEnum, CmdCheckData


def test_checkdata_cmd_basic() -> None:
    """Test basic functionality of CmdCheckData command creation and property access.

    Validates that CmdCheckData objects are properly initialized with the correct
    parameters and that all properties (ops, address, mask, count, num_bytes) can
    be accessed and modified correctly. Also verifies header parameter calculations
    and string representation.
    """
    cmd = CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0, mask=0x00000001, count=5)
    assert cmd.num_bytes == 4
    assert cmd.ops == CheckDataOpsEnum.ANY_CLEAR
    assert cmd.address == 0
    assert cmd.mask == 0x00000001
    assert cmd.count == 5

    assert cmd._header.param == 20
    cmd.num_bytes = 1
    assert cmd._header.param == 17

    cmd.ops = CheckDataOpsEnum.ALL_CLEAR
    assert cmd._header.param == 1

    assert "CmdCheckData " in repr(cmd)


def test_checkdata_export_parse() -> None:
    """Test export and parse functionality of CmdCheckData command.

    Verifies that a CmdCheckData instance can be exported to binary data
    and then parsed back to an equivalent command object. Tests the
    round-trip serialization/deserialization process.

    :raises AssertionError: If exported data length is incorrect or parsed command differs from original.
    """
    cmd = CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0, mask=0x00000001, count=5)
    data = cmd.export()
    assert len(data) == 16
    assert cmd == CmdCheckData.parse(data)


def test_checkdata_export_parse_without_count() -> None:
    """Test CheckData command export and parse functionality without count parameter.

    Verifies that a CmdCheckData object can be exported to binary data and then
    parsed back to an equivalent object. Tests the round-trip serialization
    process for CheckData commands that don't include a count parameter.

    :raises AssertionError: If the exported data length is incorrect or parsed command doesn't match original.
    """
    cmd = CmdCheckData(ops=CheckDataOpsEnum.ANY_CLEAR, address=0, mask=0x00000001)
    data = cmd.export()
    assert len(data) == 12
    assert cmd == CmdCheckData.parse(data)


def test_checkdata_info() -> None:
    """Test that CmdCheckData string representation includes count information.

    Verifies that the string representation of a CmdCheckData command object
    properly displays the count parameter value.
    """
    cmd = CmdCheckData(count=1)
    assert "Count: " in str(cmd)


def test_checkdata_invalid() -> None:
    """Test invalid CmdCheckData initialization and property assignment.

    Verifies that CmdCheckData properly validates input parameters and raises
    SPSDKError for invalid values. Tests both property assignment of invalid
    num_bytes value and constructor initialization with invalid numbytes parameter.

    :raises SPSDKError: When invalid parameters are provided to CmdCheckData.
    """
    cmd = CmdCheckData()
    with pytest.raises(SPSDKError):
        cmd.num_bytes = 6
    with pytest.raises(SPSDKError):
        cmd = CmdCheckData(numbytes=8)
