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


def test_load_cmd_preexisting():
    data = (
        b'\x1c\x02\x00\x00\n\x00\x00\x00\x10\x00\x00\x00_3<\xd8'
        b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\xbb\xffT\x0f+r'
    )
    cmd = parse_command(data)
    assert isinstance(cmd, CmdLoad)
    assert cmd.address == 10
    assert cmd.data[:10] == bytes(range(10))


def test_fill_cmd_byte_word():
    cmd = CmdFill(address=100, pattern=1, length=4)
    assert cmd.address == 100
    assert cmd.pattern == b'\x01\x01\x01\x01'

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_half_word():
    cmd = CmdFill(address=100, pattern=258, length=12)
    assert cmd.address == 100
    assert cmd.pattern == b'\x01\x02\x01\x02'

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_whole_word():
    cmd = CmdFill(address=100, pattern=16909060, length=8)
    assert cmd.address == 100
    assert cmd.pattern == b'\x01\x02\x03\x04'

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_length_not_defined():
    cmd = CmdFill(address=100, pattern=16909060)
    assert cmd.address == 100
    assert cmd.pattern == b'\x01\x02\x03\x04'

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_empty_word():
    with pytest.raises(ValueError):
        CmdFill(address=100, pattern=0)


def test_fill_cmd_incorrect_length():
    with pytest.raises(ValueError):
        CmdFill(address=100, pattern=0, length=9)


def test_fill_cmd_incorrect_word():
    with pytest.raises(ValueError):
        CmdFill(address=100, pattern=283678294867452)


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


def test_jump_cmd_with_spreg():
    cmd = CmdJump(address=200, argument=50, spreg=32)
    assert cmd.address == 200
    assert cmd.argument == 50
    assert cmd.spreg == 32
    assert cmd._header.count == 32
    assert cmd._header.flags == 2
    assert cmd._header.address == 200
    assert cmd._header.data == 50


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
