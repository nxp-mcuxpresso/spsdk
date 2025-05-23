#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.cmd_set import CmdSet, SetItmEnum
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_set_cmd():
    cmd = CmdSet()
    cmd_other = CmdSet(itm=SetItmEnum.MID)
    assert cmd.itm == SetItmEnum.ENG
    assert cmd.size == 8
    assert "CmdSet" in repr(cmd)

    assert cmd_other._header.param == 1
    cmd_other.itm = SetItmEnum.ENG
    assert cmd_other._header.param == 3


def test_set_cmd_eq():
    cmd = CmdSet()
    nop = CmdNop()
    cmd_other = CmdSet(itm=SetItmEnum.MID)
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_set_cmd_info():
    cmd = CmdSet()
    output = str(cmd)
    req_strings = ["Set Command ITM", "HASH Algo", "Engine", "Engine Conf"]

    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_set_cmd_export_parse():
    cmd = CmdSet()
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdSet.parse(data)


def test_set_cmd_invalid():
    class TestSetItmEnum(SpsdkEnum):
        TEST = (8, "TEST", "Test")

    with pytest.raises(SPSDKError):
        CmdSet(itm=TestSetItmEnum.TEST)
    cmd = CmdSet()
    with pytest.raises(SPSDKError):
        cmd.engine = TestSetItmEnum.TEST
    with pytest.raises(SPSDKError):
        cmd.itm = TestSetItmEnum.TEST
