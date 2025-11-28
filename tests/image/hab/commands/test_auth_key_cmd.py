#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB Authentication Data Command tests.

This module contains comprehensive test cases for the HAB (High Assurance Boot)
Authentication Data Command functionality, validating command creation,
manipulation, and serialization operations.
"""

import pytest

from spsdk.image.hab.commands.cmd_auth_data import AuthDataFlagsEnum, CmdAuthData
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.constants import EngineEnum


def test_auth_data_cmd_basic() -> None:
    """Test basic functionality of CmdAuthData command.

    Verifies that CmdAuthData initializes with correct default values and that
    property setters work correctly. Tests default flags, key index, engine,
    engine configuration, location, size, and string representation.
    Also validates that setting flags updates the internal header parameter.
    """
    cmd = CmdAuthData()
    assert cmd.flags == AuthDataFlagsEnum.CLR
    assert cmd.key_index == 1
    assert cmd.engine == EngineEnum.ANY
    assert cmd.engine_cfg == 0
    assert cmd.location == 0
    assert cmd.size == 12

    assert "CmdAuthData" in repr(cmd)

    cmd.flags = AuthDataFlagsEnum.ABS
    assert cmd._header.param == AuthDataFlagsEnum.ABS


def test_auth_data_cmd_clear() -> None:
    """Test clearing functionality of CmdAuthData command.

    Verifies that the CmdAuthData command can be properly cleared, resetting
    its size to the base value while maintaining proper structure. Tests the
    command's ability to append data and then reset to initial state.

    :raises AssertionError: If any of the size or length assertions fail.
    """
    cmd = CmdAuthData()
    assert cmd.size == 12
    cmd.append(3, 10)
    assert len(cmd[0]) == 2
    assert cmd.size == 20
    cmd.clear()
    assert cmd.size == 12


def test_auth_data_cmd_length_data() -> None:
    """Test authentication data command length calculation with multiple data entries.

    Verifies that the CmdAuthData command correctly tracks its length when multiple
    data entries are appended to it. The test appends two entries and confirms
    the command length equals the number of entries added.
    """
    cmd = CmdAuthData()
    cmd.append(3, 10)
    cmd.append(4, 6)
    assert len(cmd) == 2


def test_auth_data_cmd_pop_append() -> None:
    """Test authentication data command pop and append operations.

    Verifies that the CmdAuthData command correctly handles appending data
    and popping data blocks, ensuring the size is updated appropriately
    after each operation.
    """
    cmd = CmdAuthData(
        flags=AuthDataFlagsEnum.CLR, key_index=3, engine=EngineEnum.CSU, engine_cfg=1, location=1
    )
    cmd.append(3, 10)
    assert cmd.size == 20
    cmd.pop(0)
    assert cmd.size == 12


def test_auth_data_cmd_export_parse() -> None:
    """Test authentication data command export and parse functionality.

    Verifies that CmdAuthData can be properly exported to binary format
    and then parsed back to recreate the original command object.

    :raises AssertionError: If exported data length is incorrect or parsed command doesn't match original.
    """
    cmd = CmdAuthData()
    cmd.append(0xBABA, 0xDEDA)
    data = cmd.export()
    assert len(data) == 20
    assert len(data) == cmd.size
    assert cmd == CmdAuthData.parse(data)


def test_auth_data_cmd_get_set_iter() -> None:
    """Test authentication data command getter, setter, and iterator functionality.

    Validates that CmdAuthData supports list-like operations including item access,
    modification, iteration, and proper StopIteration exception handling when
    iterator is exhausted.

    :raises StopIteration: When iterator reaches the end of data pairs.
    """
    cmd = CmdAuthData(
        flags=AuthDataFlagsEnum.CLR, key_index=3, engine=EngineEnum.CSU, engine_cfg=1, location=1
    )
    cmd.append(0xBABA, 0xDEDA)
    cmd[0] = (5, 6)
    assert cmd[0] == (5, 6)
    cmd.append(9, 8)
    my_iter = iter(cmd)
    assert next(my_iter) == (5, 6)
    assert next(my_iter) == (9, 8)
    with pytest.raises(StopIteration):
        next(my_iter)


def test_auth_data_cmd_info() -> None:
    """Test the string representation of CmdAuthData command.

    This test verifies that the CmdAuthData command object properly formats
    its string representation with all required information including flags,
    key index, engine configuration, location, start address, and length.
    """
    cmd = CmdAuthData(
        flags=AuthDataFlagsEnum.CLR, key_index=3, engine=EngineEnum.CSU, engine_cfg=1, location=1
    )
    cmd.append(3, 10)
    output = str(cmd)
    req_strings = [
        'Command "Authenticate Data',
        "Flag:",
        "Key index:",
        "Engine:",
        "Engine Conf:",
        "Location:",
        "Start:",
        "Length:",
    ]
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_auth_data_cmd_equality() -> None:
    """Test equality comparison for CmdAuthData command objects.

    Verifies that CmdAuthData objects correctly implement equality comparison
    by testing against different object types and configurations. Tests include
    comparison with different command types, self-comparison, and comparison
    with objects having different parameter values.
    """
    cmd = CmdAuthData()
    nop = CmdNop()
    cmd_other = CmdAuthData(
        flags=AuthDataFlagsEnum.ABS, key_index=2, engine=EngineEnum.DCP, engine_cfg=1, location=1
    )
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other
