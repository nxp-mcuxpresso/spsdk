#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB Initialize Command test suite.

This module contains comprehensive test cases for the HAB (High Assurance Boot)
Initialize command functionality, covering command creation, parsing, serialization,
and various edge cases.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_initialize import CmdInitialize
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.constants import EngineEnum
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_init_cmd() -> None:
    """Test CmdInitialize command functionality.

    Validates the initialization of CmdInitialize command object, including
    default values, property assignments, and string representation. Tests
    engine type setting and its effect on header parameters.

    :raises AssertionError: If any of the tested conditions fail.
    """
    cmd = CmdInitialize()
    assert cmd.engine == EngineEnum.ANY
    assert cmd.size == 4

    assert cmd._header.param == 0
    cmd.engine = EngineEnum.CSU
    assert cmd._header.param == 10

    assert "CmdInitialize " in repr(cmd)


def test_init_cmd_base() -> None:
    """Test basic functionality of CmdInitialize command.

    Verifies that the CmdInitialize command properly manages its header length
    and size when appending data and clearing the command. Tests the initial
    state, data appending behavior, and reset functionality.

    :raises AssertionError: If any of the expected values don't match actual values.
    """
    cmd = CmdInitialize()
    cmd.append(0xFF)
    assert cmd._header.length == 8
    assert cmd._header.size == 4
    cmd.clear()
    assert cmd._header.length == 4


def test_init_cmd_info() -> None:
    """Test that CmdInitialize command string representation contains required information.

    Verifies that the string output of a CmdInitialize command object includes
    all expected components: command name, engine information, and value details.

    :raises AssertionError: If any required string is missing from the command output.
    """
    cmd = CmdInitialize(data=[1, 0])
    output = str(cmd)
    req_strings = ["Initialize Command ", "Engine:", "Value: "]
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not int output: {output}"


def test_init_cmd_export_parse_no_data() -> None:
    """Test initialization command export and parse with no data.

    Verifies that a CmdInitialize command with default/empty configuration
    can be exported to binary data and then parsed back to recreate the
    original command object. The test ensures the exported data has the
    expected length of 4 bytes and that the round-trip conversion preserves
    the command structure.
    """
    cmd = CmdInitialize()
    data = cmd.export()
    assert len(data) == 4
    assert cmd == CmdInitialize.parse(data)


def test_init_cmd_export_parse_with_data() -> None:
    """Test CmdInitialize export and parse functionality with data.

    Verifies that a CmdInitialize command with appended data can be exported
    to binary format and then parsed back to recreate the original command
    object. Tests the round-trip serialization/deserialization process.

    :raises AssertionError: If exported data length is incorrect or parsed command doesn't match original.
    """
    cmd = CmdInitialize()
    cmd.append(5)
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdInitialize.parse(data)


def test_init_cmd_export_parse_with_offset() -> None:
    """Test parsing of CmdInitialize command with offset in raw data.

    This test verifies that the CmdInitialize.parse() method correctly handles
    raw data that includes an offset (first 4 bytes are skipped) and properly
    parses the command structure with appended values.

    :raises AssertionError: If parsed command length is not 2 or if the parsed object is not a CmdInitialize instance.
    """
    # raw_data is made from appending 5,6 into cmd init
    raw_data = b"\xb4\x00\x0c\x00\x00\x00\x00\x05\x00\x00\x00\x06"
    raw_data = b"\x01\x02\x03\x04" + raw_data
    cmd = CmdInitialize.parse(raw_data[4:])
    assert len(cmd) == 2
    assert isinstance(cmd, CmdInitialize)


def test_init_cmd_pop_append() -> None:
    """Test the append and pop functionality of CmdInitialize command.

    Verifies that the CmdInitialize command correctly supports adding and removing
    elements using append() and pop() methods, and that the length is properly
    maintained throughout these operations.
    """
    cmd = CmdInitialize()
    assert len(cmd) == 0
    cmd.append(8)
    assert len(cmd) == 1
    cmd.pop(0)
    assert len(cmd) == 0


def test_init_cmd_get_set_item() -> None:
    """Test CmdInitialize get/set item operations and iteration functionality.

    Validates that CmdInitialize command supports item assignment, retrieval,
    and proper iterator behavior including StopIteration exception handling.

    :raises StopIteration: When iterator is exhausted and next() is called again.
    """
    cmd = CmdInitialize(engine=EngineEnum.SW)
    cmd.append(5)
    cmd[0] = [5, 6]  # type: ignore
    assert cmd[0] == [5, 6]
    my_iter = iter(cmd)
    assert next(my_iter) == [5, 6]
    with pytest.raises(StopIteration):
        next(my_iter)


def test_init_cmd_equality() -> None:
    """Test equality comparison for CmdInitialize command objects.

    Verifies that CmdInitialize objects correctly implement equality comparison
    by testing against different object types and configurations. Tests include
    comparison with different command types, self-comparison, and comparison
    with commands having different parameters.

    :raises AssertionError: If equality comparisons don't behave as expected.
    """
    cmd = CmdInitialize()
    nop = CmdNop()
    cmd_other = CmdInitialize(engine=EngineEnum.OCOTP)
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_init_cmd_invalid() -> None:
    """Test invalid operations on CmdInitialize command.

    This test verifies that CmdInitialize properly validates input parameters
    and raises appropriate exceptions for invalid operations including setting
    invalid engine types, appending invalid values, and accessing invalid indices.

    :raises SPSDKError: When invalid engine is assigned or used in constructor.
    :raises SPSDKError: When invalid value is appended to command.
    :raises SPSDKError: When invalid index is used in pop operation.
    """

    class TestEnumEngine(SpsdkEnum):
        """Test enumeration engine for SPSDK operations.

        This enumeration defines test-specific constants used in SPSDK testing
        scenarios, providing standardized test identifiers and descriptions.

        :cvar TEST: Test enumeration value with identifier and description.
        """

        TEST = (55, "TEST", "Test")

    cmd = CmdInitialize()
    test_engine: EngineEnum = TestEnumEngine.TEST  # type: ignore[assignment]
    with pytest.raises(SPSDKError):
        cmd.engine = test_engine
    with pytest.raises(SPSDKError):
        CmdInitialize(engine=test_engine)
    with pytest.raises(SPSDKError):
        cmd.append(value=0xFFFFFFFF)
    with pytest.raises(SPSDKError):
        cmd.pop(index=77)
