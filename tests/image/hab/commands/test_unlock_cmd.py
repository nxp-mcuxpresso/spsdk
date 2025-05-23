#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_unlock import (
    CmdUnlockCAAM,
    CmdUnlockOCOTP,
    CmdUnlockSNVS,
    UnlockCAAMFeaturesEnum,
    UnlockOCOTPFeaturesEnum,
    UnlockSNVSFeaturesEnum,
)
from spsdk.image.hab.commands.cmd_unlock import (
    CmdUnlockAny,
)
from spsdk.image.hab.constants import EngineEnum
from spsdk.image.hab.hab_header import CmdHeader


def test_unlock_cmd_base():
    cmd = CmdUnlockAny()
    assert cmd.engine == EngineEnum.ANY
    assert cmd.size == 8
    assert "CmdUnlock" in str(cmd)
    assert cmd._header.param == 0

    cmd = CmdUnlockAny(EngineEnum.CSU)
    assert cmd._header.param == 10


def test_unlock_cmd_export_parse():
    cmd = CmdUnlockAny()
    data = cmd.export()
    assert len(data) == 8
    assert cmd == CmdUnlockAny.parse(data)


def test_unlock_cmd_equality():
    cmd = CmdUnlockAny()
    nop = CmdNop()
    cmd_other = CmdUnlockAny(engine=EngineEnum.DCP)

    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_unlock_cmd_info():
    cmd = CmdUnlockAny()
    output = str(cmd)
    req_strings = ["Unlock Command", "Features:", "UID:"]
    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"


def test_unlock_snvs():
    """Test Unlock SNVS command"""
    cmd = CmdUnlockSNVS(UnlockSNVSFeaturesEnum.LP_SWR.tag | UnlockSNVSFeaturesEnum.ZMK_WRITE.tag)
    assert cmd.engine == EngineEnum.SNVS
    assert cmd.size == CmdHeader.SIZE + 4
    assert cmd.unlock_lp_swr
    assert cmd.unlock_zmk_write
    cmd = CmdUnlockSNVS()
    assert not cmd.unlock_lp_swr
    assert not cmd.unlock_zmk_write

    assert str(cmd)

    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_caam():
    cmd = CmdUnlockCAAM(features=UnlockCAAMFeaturesEnum.MID)
    assert cmd.features == 1
    assert cmd.unlock_mid
    assert not cmd.unlock_mfg
    assert not cmd.unlock_rng
    assert "CmdUnlockCAAM" in str(cmd)

    assert str(cmd)

    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_ocotp():
    cmd = CmdUnlockOCOTP(
        features=UnlockOCOTPFeaturesEnum.FIELD_RETURN.tag
        | UnlockOCOTPFeaturesEnum.JTAG.tag
        | UnlockOCOTPFeaturesEnum.SCS.tag,
        uid=0x123456789,
    )

    assert cmd.unlock_fld_rtn
    assert not cmd.unlock_srk_rvk
    assert "CmdUnlockOCOTP" in str(cmd)

    assert "UID" in str(cmd)
    assert "UID" not in str(CmdUnlockOCOTP())

    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert data == cmd2.export()
    assert cmd == cmd2


def test_unlock_parse_others():
    cmd = CmdUnlockAny(engine=EngineEnum.SRTC)
    assert "CmdUnlock" in str(cmd)
    data = cmd.export()
    cmd2 = CmdUnlockAny.parse(data)
    assert cmd == cmd2


def test_need_uid():
    positive = [
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.FIELD_RETURN.tag),
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.JTAG.tag),
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.SCS.tag),
    ]
    negative = [
        CmdUnlockAny.need_uid(EngineEnum.OCOTP, UnlockOCOTPFeaturesEnum.SRK_REVOKE.tag),
        CmdUnlockAny.need_uid(EngineEnum.CAAM, 0b001),
        CmdUnlockAny.need_uid(EngineEnum.CAAM, 0b010),
        CmdUnlockAny.need_uid(EngineEnum.CAAM, 0b100),
        CmdUnlockAny.need_uid(EngineEnum.ANY, 0b1111),
    ]
    assert all(positive)
    assert not all(negative)
