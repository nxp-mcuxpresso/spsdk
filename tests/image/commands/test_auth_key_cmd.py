#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image.commands import EnumAuthDat
from spsdk.image.segments import CmdAuthData, CmdNop, EnumEngine


def test_auth_data_cmd_basic():
    cmd = CmdAuthData()
    assert cmd.flags == EnumAuthDat.CLR
    assert cmd.key_index == 1
    assert cmd.engine == EnumEngine.ANY
    assert cmd.engine_cfg == 0
    assert cmd.location == 0
    assert cmd.size == 12

    assert "CmdAuthData" in repr(cmd)

    cmd.flags = EnumAuthDat.ABS
    assert cmd._header.param == EnumAuthDat.ABS


def test_auth_data_cmd_clear():
    cmd = CmdAuthData()
    assert cmd.size == 12
    cmd.append(3, 10)
    assert len(cmd[0]) == 2
    assert cmd.size == 20
    cmd.clear()
    assert cmd.size == 12


def test_auth_data_cmd_length_data():
    cmd = CmdAuthData()
    cmd.append(3, 10)
    cmd.append(4, 6)
    assert len(cmd) == 2


def test_auth_data_cmd_pop_append():
    cmd = CmdAuthData(
        flags=EnumAuthDat.CLR, key_index=3, engine=EnumEngine.CSU, engine_cfg=1, location=1
    )
    cmd.append(3, 10)
    assert cmd.size == 20
    cmd.pop(0)
    assert cmd.size == 12


def test_auth_data_cmd_export_parse():
    cmd = CmdAuthData()
    cmd.append(0xBABA, 0xDEDA)
    data = cmd.export()
    assert len(data) == 20
    assert len(data) == cmd.size
    assert cmd == CmdAuthData.parse(data)


def test_auth_data_cmd_get_set_iter():
    cmd = CmdAuthData(
        flags=EnumAuthDat.CLR, key_index=3, engine=EnumEngine.CSU, engine_cfg=1, location=1
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


def test_auth_data_cmd_info():
    cmd = CmdAuthData(
        flags=EnumAuthDat.CLR, key_index=3, engine=EnumEngine.CSU, engine_cfg=1, location=1
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


def test_auth_data_cmd_equality():
    cmd = CmdAuthData()
    nop = CmdNop()
    cmd_other = CmdAuthData(
        flags=EnumAuthDat.ABS, key_index=2, engine=EnumEngine.DCP, engine_cfg=1, location=1
    )
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other
