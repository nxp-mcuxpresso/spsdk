#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.sbfile.commands import CmdNop, CmdCall, CmdErase, CmdFill, CmdJump, CmdLoad, CmdMemEnable, CmdProg, CmdReset
from spsdk.sbfile.commands import VersionCheckType, CmdVersionCheck, CmdKeyStoreBackup, CmdKeyStoreRestore
from spsdk.sbfile.commands import CmdTag, parse_command
from spsdk.mboot import ExtMemId


def test_nop_cmd():
    cmd = CmdNop()
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_tag_cmd():
    cmd = CmdTag()
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_load_cmd():
    cmd = CmdLoad(address=100, data=b'\x00' * 100)
    assert cmd.address == 100
    assert cmd.data == bytearray([0] * 100)
    assert cmd.info()

    cmd.data = cmd.data + b'\x10'
    assert len(cmd.data) == 101

    data = cmd.export()
    assert len(data) == 128
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd():
    cmd = CmdFill(address=100, pattern=b'\x00\x01\x02\x00')
    assert cmd.address == 100
    assert cmd.pattern == b'\x00\x01\x02\x00'
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    cmd = CmdFill(address=100, pattern=b'\x00\x01\x02\x00\xFF\xFE\xFD\xFC')
    data = cmd.export()
    assert len(data) == 32
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    with pytest.raises(ValueError):
        CmdFill(address=100, pattern=b'')

    with pytest.raises(ValueError):
        CmdFill(address=100, pattern=b'\x00\x01')

    with pytest.raises(ValueError):
        CmdFill(address=100, pattern=b'\x00\x01\x02\x00\xFF')


def test_jump_cmd():
    cmd = CmdJump(address=100, argument=10, spreg=None)
    assert cmd.address == 100
    assert cmd.argument == 10
    assert cmd.spreg is None
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_call_cmd():
    cmd = CmdCall(address=100, argument=10)
    assert cmd.address == 100
    assert cmd.argument == 10
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_erase_cmd():
    cmd = CmdErase(address=100, length=10, flags=0)
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.flags == 0
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_reset_cmd():
    cmd = CmdReset()
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_mem_enable_cmd():
    cmd = CmdMemEnable(address=100, size=10, mem_type=ExtMemId.MMC_CARD)
    assert cmd.address == 100
    assert cmd.size == 10
    assert cmd.mem_type == ExtMemId.MMC_CARD
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_prog_cmd():
    cmd = CmdProg()
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_version_check():
    """ Test SB command `CmdVersionCheck` """
    cmd = CmdVersionCheck(VersionCheckType.NON_SECURE_VERSION, 0x16)
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.version == 0x16
    assert cmd.type == VersionCheckType.NON_SECURE_VERSION


def test_keystore_backup():
    """ Test SB command `CmdKeyStoreBackup` """
    cmd = CmdKeyStoreBackup(1000, 1)
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.address == 1000
    assert cmd.controller_id == 1


def test_keystore_restore():
    """ Test SB command `CmdKeyStoreRestore` """
    cmd = CmdKeyStoreRestore(1000, 1)
    assert cmd.info()

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.address == 1000
    assert cmd.controller_id == 1


def test_parse_invalid_command_tag():
    with pytest.raises(ValueError):
        parse_command(b'\xEE' * 16)
