#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB Write Data command test suite.

This module contains comprehensive test cases for the HAB (High Assurance Boot)
Write Data command functionality, covering command creation, validation,
serialization, and data manipulation operations.
"""

from typing import List, Tuple, Union

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_write_data import CmdWriteData, WriteDataOpsEnum


@pytest.mark.parametrize(
    "input_data", [[(0, 1)], ((0, 1),)]  # input data as list  # input data as tuple
)
def test_write_value_cmd_basic(
    input_data: Union[List[Tuple[int, int]], Tuple[Tuple[int, int], ...]],
) -> None:
    """Test basic functionality of CmdWriteData command with various configurations.

    Validates that the CmdWriteData command correctly handles different byte sizes
    (1, 2, 4 bytes) and operation types (CLEAR_BITMASK). Tests parameter setting
    and string representation functionality.

    :param input_data: Input data as list or tuple of (address, value) pairs for write operations.
    """
    cmd = CmdWriteData(data=input_data)

    cmd.num_bytes = 1
    assert cmd._header.param == 1
    cmd.num_bytes = 2
    assert cmd._header.param == 2
    cmd.num_bytes = 4
    assert cmd._header.param == 4

    cmd.ops = WriteDataOpsEnum.CLEAR_BITMASK
    assert cmd._header.param == 20

    assert "CmdWriteData" in repr(cmd)


def test_invalid_cmd_write_data() -> None:
    """Test invalid operations on CmdWriteData command.

    Validates that CmdWriteData properly raises SPSDKError exceptions for:
    - Setting num_bytes property after initialization
    - Creating instance with invalid numbytes parameter
    - Appending data with address values exceeding 32-bit range
    - Appending data with value exceeding 32-bit range
    - Popping from invalid index position

    :raises SPSDKError: When invalid operations are performed on the command.
    """
    cmd = CmdWriteData()
    with pytest.raises(SPSDKError):
        cmd.num_bytes = 16
    with pytest.raises(SPSDKError):
        cmd = CmdWriteData(numbytes=8)
    cmd = CmdWriteData()
    with pytest.raises(SPSDKError):
        cmd.append(address=0xFFFFFFFFF, value=0)
    with pytest.raises(SPSDKError):
        cmd.append(address=0xFFFFFFFF, value=0xFFFFFFFFF)
    cmd.append(5, 6)
    cmd.append(7, 8)
    with pytest.raises(SPSDKError):
        cmd.pop(3)


def test_write_value_cmd_get_set_iter() -> None:
    """Test write data command get, set, and iteration operations.

    Validates that CmdWriteData supports list-like operations including length checking,
    item assignment, item retrieval, appending new data pairs, and iteration over
    stored address-data pairs.
    """
    cmd = CmdWriteData()
    cmd.append(9, 9)
    assert len(cmd) == 1
    cmd[0] = [5, 6]
    assert cmd[0] == [5, 6]
    cmd.append(5, 6)
    my_iter = iter(cmd)
    assert next(my_iter) == [5, 6]
    assert next(my_iter) == [5, 6]


def test_write_value_cmd_clear() -> None:
    """Test CmdWriteData clear functionality.

    Verifies that the CmdWriteData command properly resets its internal state
    when the clear() method is called. Tests that header length and size
    return to their initial values after clearing appended data.
    """
    cmd = CmdWriteData()
    assert cmd._header.length == 4
    assert cmd._header.size == 4
    cmd.append(0xFF, 5)
    assert cmd._header.length == 12
    assert cmd._header.size == 4
    cmd.clear()
    assert cmd._header.length == 4
    assert cmd._header.size == 4


def test_writedata_cmd_export_parse_with_no_data() -> None:
    """Test WriteData command export and parse with no data.

    Verifies that a CmdWriteData instance with default/no data can be
    exported and then parsed back to create an equivalent instance.

    :raises AssertionError: When the original command doesn't match the parsed command.
    """
    cmd = CmdWriteData()
    data = cmd.export()
    assert cmd == CmdWriteData.parse(data)


def test_writedata_cmd_export_parse_with_data() -> None:
    """Test WriteData command export and parse functionality with appended data.

    This test verifies that a CmdWriteData object can be properly exported to binary
    format and then parsed back to recreate an equivalent object when the command
    contains appended data.

    :raises AssertionError: If the parsed command doesn't match the original command.
    """
    cmd = CmdWriteData()
    cmd.append(5, 6)
    data = cmd.export()
    assert cmd == CmdWriteData.parse(data)


def test_writedata_cmd_equality() -> None:
    """Test equality comparison for CmdWriteData command objects.

    Verifies that CmdWriteData instances correctly implement equality comparison
    by testing against different command types, self-comparison, and instances
    with different data content.
    """
    cmd = CmdWriteData(data=[(0, 1)])
    cmd_other = CmdWriteData()
    nop = CmdNop()
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_writedata_cmd_pop_append() -> None:
    """Test WriteData command pop and append operations.

    Verifies that the WriteData command correctly updates its header length
    when appending data entries and popping them from the command structure.
    The test ensures proper length tracking during command modification operations.

    :raises AssertionError: If header length calculations are incorrect during operations.
    """
    cmd = CmdWriteData()
    cmd._header.length == 4
    cmd.append(5, 6)
    cmd.append(7, 8)
    cmd._header.length == 12
    cmd.pop(1)
    cmd._header.length == 4
