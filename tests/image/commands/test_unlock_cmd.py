#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image import CmdNop, CmdUnlock, CmdUnlockSNVS, EnumEngine
from spsdk.image.header import CmdHeader


def test_unlock_cmd_base():
    cmd = CmdUnlock()
    assert cmd.engine == EnumEngine.ANY
    assert cmd.size == 16
    assert "CmdUnlock" in repr(cmd)
    assert cmd._header.param == 0

    cmd = CmdUnlock(EnumEngine.CSU)
    assert cmd._header.param == 10


def test_unlock_cmd_export_parse():
    cmd = CmdUnlock()
    data = cmd.export()
    assert len(data) == 16
    assert cmd == CmdUnlock.parse(data)


def test_unlock_cmd_equality():
    cmd = CmdUnlock()
    nop = CmdNop()
    cmd_other = CmdUnlock(engine=EnumEngine.DCP)

    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_unlock_cmd_info():
    cmd = CmdUnlock()
    output = cmd.info()
    req_strings = ["Unlock Command", "Features:", "UID:"]
    for req_string in req_strings:
        assert req_string in output, f'string {req_string} is not in the output: {output}'


def test_unlock_snvs():
    """Test Unlock SNVS command"""
    cmd = CmdUnlockSNVS(CmdUnlockSNVS.FEATURE_UNLOCK_LP_SWR | CmdUnlockSNVS.FEATURE_UNLOCK_ZMK_WRITE)
    assert cmd.engine == EnumEngine.SNVS
    assert cmd.size == CmdHeader.SIZE + 4
    assert cmd.unlock_lp_swr
    assert cmd.unlock_zmk_write
    cmd = CmdUnlockSNVS()
    assert not cmd.unlock_lp_swr
    assert not cmd.unlock_zmk_write
