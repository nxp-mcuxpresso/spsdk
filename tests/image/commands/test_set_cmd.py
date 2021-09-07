#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk import SPSDKError
from spsdk.image import CmdNop, CmdSet, EnumItm


def test_set_cmd():
    cmd = CmdSet()
    cmd_other = CmdSet(itm=EnumItm.MID)
    assert cmd.itm == EnumItm.ENG
    assert cmd.size == 8
    assert "CmdSet" in repr(cmd)

    assert cmd_other._header.param == 1
    cmd_other.itm = 0x03
    assert cmd_other._header.param == 3


def test_set_cmd_eq():
    cmd = CmdSet()
    nop = CmdNop()
    cmd_other = CmdSet(itm=EnumItm.MID)
    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_set_cmd_info():
    cmd = CmdSet()
    output = cmd.info()
    req_strings = ["Set Command ITM", "HASH Algo", "Engine", "Engine Conf"]

    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_set_cmd_export_parse():
    cmd = CmdSet()
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdSet.parse(data)


def test_set_cmd_invalid():
    with pytest.raises(SPSDKError):
        CmdSet(itm=8)
    cmd = CmdSet()
    with pytest.raises(SPSDKError):
        cmd.hash_algorithm = 55
    with pytest.raises(SPSDKError):
        cmd.engine = 0xFE
    with pytest.raises(SPSDKError):
        cmd.itm = 55
