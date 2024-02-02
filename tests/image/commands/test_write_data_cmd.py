#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.commands import CmdNop, CmdWriteData, EnumWriteOps


@pytest.mark.parametrize(
    "input_data", [[(0, 1)], ((0, 1),)]  # input data as list  # input data as tuple
)
def test_write_value_cmd_basic(input_data):
    """Basic test with input data in format: list"""
    cmd = CmdWriteData(data=input_data)

    cmd.num_bytes = 1
    assert cmd._header.param == 1
    cmd.num_bytes = 2
    assert cmd._header.param == 2
    cmd.num_bytes = 4
    assert cmd._header.param == 4

    cmd.ops = EnumWriteOps.CLEAR_BITMASK
    assert cmd._header.param == 20

    assert "CmdWriteData" in repr(cmd)


def test_invalid_cmd_write_data():
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


def test_write_value_cmd_get_set_iter():
    cmd = CmdWriteData()
    cmd.append(9, 9)
    assert len(cmd) == 1
    cmd[0] = [5, 6]
    assert cmd[0] == [5, 6]
    cmd.append(5, 6)
    my_iter = iter(cmd)
    assert next(my_iter) == [5, 6]
    assert next(my_iter) == [5, 6]


def test_write_value_cmd_clear():
    cmd = CmdWriteData()
    assert cmd._header.length == 4
    assert cmd._header.size == 4
    cmd.append(0xFF, 5)
    assert cmd._header.length == 12
    assert cmd._header.size == 4
    cmd.clear()
    assert cmd._header.length == 4
    assert cmd._header.size == 4


def test_writedata_cmd_export_parse_with_no_data():
    cmd = CmdWriteData()
    data = cmd.export()
    assert cmd == CmdWriteData.parse(data)


def test_writedata_cmd_export_parse_with_data():
    cmd = CmdWriteData()
    cmd.append(5, 6)
    data = cmd.export()
    assert cmd == CmdWriteData.parse(data)


def test_writedata_cmd_equality():
    cmd = CmdWriteData(data=[(0, 1)])
    cmd_other = CmdWriteData()
    nop = CmdNop()
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_writedata_cmd_pop_append():
    cmd = CmdWriteData()
    cmd._header.length == 4
    cmd.append(5, 6)
    cmd.append(7, 8)
    cmd._header.length == 12
    cmd.pop(1)
    cmd._header.length == 4
