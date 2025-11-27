#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB DCD segment testing module.

This module contains comprehensive test cases for the HAB (High Assurance Boot)
DCD (Device Configuration Data) segment functionality in SPSDK.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_check_data import CheckDataOpsEnum, CmdCheckData
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.segments.seg_dcd import SegDCD


def test_segDCD() -> None:
    """Test SegDCD segment creation and string representation.

    Verifies that a SegDCD object can be instantiated and that its string
    representation contains the expected "DCD <Commands:" prefix.
    """
    dcd_seg = SegDCD()
    assert "DCD <Commands:" in repr(dcd_seg)


def test_segDCD_set_get_iter() -> None:
    """Test SegDCD set, get and iteration functionality.

    Validates that SegDCD segment supports list-like operations including
    appending commands, setting/getting commands by index, and proper
    iteration behavior with StopIteration exception handling.
    """
    dcd_seg = SegDCD(0x40)
    dcd_seg.append(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    dcd_seg.append(CmdNop())
    dcd_seg[1] = CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    assert dcd_seg[1] == CmdCheckData(
        ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    dcd_seg.append(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    my_iter = iter(dcd_seg)
    assert next(my_iter) == CmdCheckData(
        ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    assert next(my_iter) == CmdCheckData(
        ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    assert next(my_iter) == CmdCheckData(
        ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001
    )
    with pytest.raises(StopIteration):
        next(my_iter)


def test_segDCD_pop_append() -> None:
    """Test DCD segment pop and append operations.

    Verifies that commands can be appended to a DCD segment and then popped
    in the correct order, ensuring the string representations contain the
    expected command names.

    :raises AssertionError: If popped commands don't contain expected strings.
    """
    dcd_seg = SegDCD(0x40)
    dcd_seg.append(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    dcd_seg.append(CmdNop())
    output = dcd_seg.pop(1)
    assert 'Command "No Operation' in str(output)
    output = dcd_seg.pop(0)
    assert 'Command "Check Data' in str(output)


def test_segDCD_clear() -> None:
    """Test DCD segment clear functionality.

    Verifies that the SegDCD clear method properly resets the segment by removing
    all commands while maintaining correct header properties. Tests that the header
    length is reset to 4 bytes after clearing commands.
    """
    dcd_seg = SegDCD(0x40)
    dcd_seg.append(
        CmdCheckData(ops=CheckDataOpsEnum.ALL_CLEAR, address=0x307900C4, mask=0x00000001)
    )
    assert len(dcd_seg) == len(dcd_seg._commands)
    assert dcd_seg._header.length == 16
    assert dcd_seg._header.size == 4
    dcd_seg.clear()
    assert dcd_seg._header.length == 4
    assert dcd_seg._header.size == 4


def test_segDCD_eq() -> None:
    """Test equality comparison for SegDCD instances.

    Verifies that a SegDCD object is equal to itself, ensuring the equality
    operator works correctly for DCD segment objects.
    """
    dcd_seg = SegDCD()
    assert dcd_seg == dcd_seg


def test_segDCD_invalid_append_pop() -> None:
    """Test invalid append and pop operations on DCD segment.

    Verifies that SegDCD properly raises SPSDKError when attempting to append
    an invalid command type or pop from an invalid index position.

    :raises SPSDKError: When invalid command is appended or invalid index is popped.
    """
    dcd_seg = SegDCD()
    with pytest.raises(SPSDKError, match="Invalid command"):
        dcd_seg.append(cmd=5)  # type: ignore
    with pytest.raises(SPSDKError, match="Can not pop item from dcd segment"):
        dcd_seg.pop(index=100)  # type: ignore
