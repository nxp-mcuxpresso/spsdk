#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.commands import CmdInitialize, CmdNop, EnumEngine
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_init_cmd():
    cmd = CmdInitialize()
    assert cmd.engine == EnumEngine.ANY
    assert cmd.size == 4

    assert cmd._header.param == 0
    cmd.engine = EnumEngine.CSU
    assert cmd._header.param == 10

    assert "CmdInitialize " in repr(cmd)


def test_init_cmd_base():
    cmd = CmdInitialize()
    cmd.append(0xFF)
    assert cmd._header.length == 8
    assert cmd._header.size == 4
    cmd.clear()
    assert cmd._header.length == 4


def test_init_cmd_info():
    cmd = CmdInitialize(data=(1, 0))
    output = str(cmd)
    req_strings = ["Initialize Command ", "Engine:", "Value: "]
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not int output: {output}"


def test_init_cmd_export_parse_no_data():
    cmd = CmdInitialize()
    data = cmd.export()
    assert len(data) == 4
    assert cmd == CmdInitialize.parse(data)


def test_init_cmd_export_parse_with_data():
    cmd = CmdInitialize()
    cmd.append(5)
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdInitialize.parse(data)


def test_init_cmd_export_parse_with_offset():
    # raw_data is made from appending 5,6 into cmd init
    raw_data = b"\xb4\x00\x0c\x00\x00\x00\x00\x05\x00\x00\x00\x06"
    raw_data = b"\x01\x02\x03\x04" + raw_data
    cmd = CmdInitialize.parse(raw_data[4:])
    assert len(cmd) == 2
    assert isinstance(cmd, CmdInitialize)


def test_init_cmd_pop_append():
    cmd = CmdInitialize()
    assert len(cmd) == 0
    cmd.append(8)
    assert len(cmd) == 1
    cmd.pop(0)
    assert len(cmd) == 0


def test_init_cmd_get_set_item():
    cmd = CmdInitialize(engine=EnumEngine.SW)
    cmd.append(5)
    cmd[0] = [5, 6]
    assert cmd[0] == [5, 6]
    my_iter = iter(cmd)
    assert next(my_iter) == [5, 6]
    with pytest.raises(StopIteration):
        next(my_iter)


def test_init_cmd_equality():
    cmd = CmdInitialize()
    nop = CmdNop()
    cmd_other = CmdInitialize(engine=EnumEngine.OCOTP)
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_init_cmd_invalid():
    class TestEnumEngine(SpsdkEnum):
        TEST = (55, "TEST", "Test")

    cmd = CmdInitialize()
    with pytest.raises(SPSDKError):
        cmd.engine = TestEnumEngine.TEST
    with pytest.raises(SPSDKError):
        CmdInitialize(engine=TestEnumEngine.TEST)
    with pytest.raises(SPSDKError):
        cmd.append(value=0xFFFFFFFF)
    with pytest.raises(SPSDKError):
        cmd.pop(index=77)
