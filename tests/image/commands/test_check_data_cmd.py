#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.segments import CmdCheckData, EnumCheckOps


def test_checkdata_cmd_basic():
    cmd = CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0, mask=0x00000001, count=5)
    assert cmd.num_bytes == 4
    assert cmd.ops == EnumCheckOps.ANY_CLEAR
    assert cmd.address == 0
    assert cmd.mask == 0x00000001
    assert cmd.count == 5

    assert cmd._header.param == 20
    cmd.num_bytes = 1
    assert cmd._header.param == 17

    cmd.ops = EnumCheckOps.ALL_CLEAR
    assert cmd._header.param == 1

    assert "CmdCheckData " in repr(cmd)


def test_checkdata_export_parse():
    cmd = CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0, mask=0x00000001, count=5)
    data = cmd.export()
    assert len(data) == 16
    assert cmd == CmdCheckData.parse(data)


def test_checkdata_export_parse_without_count():
    cmd = CmdCheckData(ops=EnumCheckOps.ANY_CLEAR, address=0, mask=0x00000001)
    data = cmd.export()
    assert len(data) == 12
    assert cmd == CmdCheckData.parse(data)


def test_checkdata_info():
    cmd = CmdCheckData(count=1)
    assert "Count: " in str(cmd)


def test_checkdata_invalid():
    cmd = CmdCheckData()
    with pytest.raises(SPSDKError):
        cmd.num_bytes = 6
    with pytest.raises(SPSDKError):
        cmd = CmdCheckData(numbytes=8)
