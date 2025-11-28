#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK HAB Set command unit tests.

This module contains comprehensive unit tests for the HAB (High Assurance Boot)
Set command functionality in SPSDK, covering command creation, validation,
serialization, and error handling scenarios.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_set import CmdSet, SetItmEnum
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_set_cmd() -> None:
    """Test CmdSet command functionality and properties.

    Validates the CmdSet command initialization with different item types,
    verifies size calculations, string representation, and parameter handling
    for both default (ENG) and MID item configurations.
    """
    cmd = CmdSet()
    cmd_other = CmdSet(itm=SetItmEnum.MID)
    assert cmd.itm == SetItmEnum.ENG
    assert cmd.size == 8
    assert "CmdSet" in repr(cmd)

    assert cmd_other._header.param == 1
    cmd_other.itm = SetItmEnum.ENG
    assert cmd_other._header.param == 3


def test_set_cmd_eq() -> None:
    """Test equality comparison for CmdSet command objects.

    Verifies that CmdSet instances correctly implement equality comparison
    by testing against different command types and configurations.

    :raises AssertionError: If equality comparisons don't behave as expected.
    """
    cmd = CmdSet()
    nop = CmdNop()
    cmd_other = CmdSet(itm=SetItmEnum.MID)
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_set_cmd_info() -> None:
    """Test Set command string representation functionality.

    Verifies that the CmdSet command object properly displays all required
    information fields in its string representation, including ITM details,
    hash algorithm, engine type, and engine configuration.

    :raises AssertionError: If any required string is missing from the output.
    """
    cmd = CmdSet()
    output = str(cmd)
    req_strings = ["Set Command ITM", "HASH Algo", "Engine", "Engine Conf"]

    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_set_cmd_export_parse() -> None:
    """Test CmdSet command export and parse functionality.

    Verifies that a CmdSet command can be exported to binary data and then
    parsed back to recreate the original command object with correct data length.

    :raises AssertionError: If exported data length is not 8 bytes or parsed command differs from original.
    """
    cmd = CmdSet()
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdSet.parse(data)


def test_set_cmd_invalid() -> None:
    """Test invalid SET command creation and property assignment.

    Verifies that CmdSet properly validates input parameters and raises SPSDKError
    when invalid enum types are used for initialization or property assignment.
    Tests both constructor validation and runtime property validation for engine
    and itm attributes.

    :raises SPSDKError: When invalid enum types are provided to constructor or properties.
    """

    class TestSetItmEnum(SpsdkEnum):
        """Test enumeration for SET command item types.

        This enumeration defines test values used for validating SET command
        item type functionality in HAB (High Assurance Boot) operations.
        """

        TEST = (8, "TEST", "Test")

    with pytest.raises(SPSDKError):
        CmdSet(itm=TestSetItmEnum.TEST)  # type: ignore[arg-type]
    cmd = CmdSet()
    with pytest.raises(SPSDKError):
        cmd.engine = TestSetItmEnum.TEST  # type: ignore[assignment]
    with pytest.raises(SPSDKError):
        cmd.itm = TestSetItmEnum.TEST  # type: ignore[assignment]
