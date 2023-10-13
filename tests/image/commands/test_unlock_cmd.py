#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.commands import (
    CmdNop,
    CmdUnlock,
    CmdUnlockCAAM,
    CmdUnlockOCOTP,
    CmdUnlockSNVS,
    EnumEngine,
)
from spsdk.image.header import CmdHeader


def test_unlock_cmd_base():
    cmd = CmdUnlock()
    assert cmd.engine == EnumEngine.ANY
    assert cmd.size == 8
    assert "CmdUnlock" in str(cmd)
    assert cmd._header.param == 0

    cmd = CmdUnlock(EnumEngine.CSU)
    assert cmd._header.param == 10


def test_unlock_cmd_export_parse():
    cmd = CmdUnlock()
    data = cmd.export()
    assert len(data) == 8
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
    output = str(cmd)
    req_strings = ["Unlock Command", "Features:", "UID:"]
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_unlock_snvs():
    """Test Unlock SNVS command"""
    cmd = CmdUnlockSNVS(
        CmdUnlockSNVS.FEATURE_UNLOCK_LP_SWR | CmdUnlockSNVS.FEATURE_UNLOCK_ZMK_WRITE
    )
    assert cmd.engine == EnumEngine.SNVS
    assert cmd.size == CmdHeader.SIZE + 4
    assert cmd.unlock_lp_swr
    assert cmd.unlock_zmk_write
    cmd = CmdUnlockSNVS()
    assert not cmd.unlock_lp_swr
    assert not cmd.unlock_zmk_write

    assert str(cmd)

    data = cmd.export()
    cmd2 = CmdUnlock.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_caam():
    cmd = CmdUnlockCAAM(features=CmdUnlockCAAM.FEATURE_UNLOCK_MID)
    assert cmd.features == 1
    assert cmd.unlock_mid
    assert not cmd.unlock_mfg
    assert not cmd.unlock_rng
    assert "CmdUnlockCAAM" in str(cmd)

    assert str(cmd)

    data = cmd.export()
    cmd2 = CmdUnlock.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_ocotp():
    cmd = CmdUnlockOCOTP(
        features=CmdUnlockOCOTP.FEATURE_UNLOCK_FLD_RTN
        | CmdUnlockOCOTP.FEATURE_UNLOCK_JTAG
        | CmdUnlockOCOTP.FEATURE_UNLOCK_SCS,
        uid=0x123456789,
    )

    assert cmd.unlock_fld_rtn
    assert not cmd.unlock_srk_rvk
    assert "CmdUnlockOCOTP" in str(cmd)

    assert "UID" in str(cmd)
    assert "UID" not in str(CmdUnlockOCOTP())

    data = cmd.export()
    cmd2 = CmdUnlock.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_parse_others():
    cmd = CmdUnlock(engine=EnumEngine.SRTC)
    assert "CmdUnlock" in str(cmd)
    data = cmd.export()
    cmd2 = CmdUnlock.parse(data)
    assert cmd == cmd2


def test_need_uid():
    positive = [
        CmdUnlock.need_uid(EnumEngine.OCOTP, CmdUnlockOCOTP.FEATURE_UNLOCK_FLD_RTN),
        CmdUnlock.need_uid(EnumEngine.OCOTP, CmdUnlockOCOTP.FEATURE_UNLOCK_JTAG),
        CmdUnlock.need_uid(EnumEngine.OCOTP, CmdUnlockOCOTP.FEATURE_UNLOCK_SCS),
    ]
    negative = [
        CmdUnlock.need_uid(EnumEngine.OCOTP, CmdUnlockOCOTP.FEATURE_UNLOCK_SRK_RVK),
        CmdUnlock.need_uid(EnumEngine.CAAM, 0b001),
        CmdUnlock.need_uid(EnumEngine.CAAM, 0b010),
        CmdUnlock.need_uid(EnumEngine.CAAM, 0b100),
        CmdUnlock.need_uid(EnumEngine.ANY, 0b1111),
    ]
    assert all(positive)
    assert not all(negative)
