#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.mboot.memories import ExtMemId
from spsdk.sbfile.sb2.commands import (
    CmdCall,
    CmdErase,
    CmdFill,
    CmdHeader,
    CmdJump,
    CmdKeyStoreBackup,
    CmdKeyStoreRestore,
    CmdLoad,
    CmdMemEnable,
    CmdNop,
    CmdProg,
    CmdReset,
    CmdTag,
    CmdVersionCheck,
    VersionCheckType,
    parse_command,
)
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_nop_cmd():
    cmd = CmdNop()
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_nop_cmd_invalid_parse():
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdNop.parse(data)


def test_tag_cmd():
    cmd = CmdTag()
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_tag_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdTag.parse(data)


def test_load_cmd():
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    assert cmd.address == 100
    assert cmd.data == bytearray([0] * 100)
    assert str(cmd)

    cmd.data = cmd.data + b"\x10"
    assert len(cmd.data) == 101

    data = cmd.export()
    assert len(data) == 128
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_load_cmd_invalid_address():
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFD


def test_load_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdLoad.parse(data)


def test_load_cmd_invalid_parse_crc():
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    cmd.export()
    with pytest.raises(SPSDKError, match="Invalid CRC in the command header"):
        CmdLoad.parse(
            data=b"Q\x02\x00\x00d\x00\x00\x00p\x00\x00\x00\x02z\xa7\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\xd1a\x13<\xf5 \x9cP\xb8\x00\x00"
        )


def test_load_cmd_preexisting():
    data = (
        b"\x1c\x02\x00\x00\n\x00\x00\x00\x10\x00\x00\x00_3<\xd8"
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\xbb\xffT\x0f+r"
    )
    cmd = parse_command(data)
    assert isinstance(cmd, CmdLoad)
    assert cmd.address == 10
    assert cmd.data[:10] == bytes(range(10))


def test_fill_cmd_byte_word():
    cmd = CmdFill(address=100, pattern=1, length=4)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x01\x01\x01"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_half_word():
    cmd = CmdFill(address=100, pattern=258, length=12)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x02\x01\x02"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_whole_word():
    cmd = CmdFill(address=100, pattern=16909060, length=8)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x02\x03\x04"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_length_not_defined():
    cmd = CmdFill(address=100, pattern=16909060)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x02\x03\x04"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_empty_word():
    result = CmdFill(address=100, pattern=0)
    assert result is not None


def test_fill_cmd_incorrect_length():
    with pytest.raises(SPSDKError):
        CmdFill(address=100, pattern=0, length=9)


def test_fill_cmd_incorrect_word():
    with pytest.raises(SPSDKError):
        CmdFill(address=100, pattern=283678294867452)


def test_fill_cmd_incorrect_address():
    cmd = CmdFill(address=100, pattern=2)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_fill_cmd_incorrect_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdFill.parse(data)


def test_jump_cmd():
    cmd = CmdJump(address=100, argument=10, spreg=None)
    assert cmd.address == 100
    assert cmd.argument == 10
    assert cmd.spreg is None
    assert str(cmd)

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
    assert "JUMP: Address=0x000000C8, Argument=0x00000032, SP=0x00000020" in str(cmd)


def test_jump_cmd_invalid():
    cmd = CmdJump(address=100, argument=10, spreg=None)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_jump_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdJump.parse(data)


def test_call_cmd():
    cmd = CmdCall(address=100, argument=10)
    assert cmd.address == 100
    assert cmd.argument == 10
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_call_cmd_invalid():
    cmd = CmdCall(address=100, argument=10)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_call_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdCall.parse(data)


def test_erase_cmd():
    cmd = CmdErase(address=100, length=10, flags=0)
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.flags == 0
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_erase_invalid():
    cmd = CmdErase(address=100, length=10, flags=0)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_erase_invalid2():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdErase.parse(data)


def test_reset_cmd():
    cmd = CmdReset()
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_reset_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdReset.parse(data)


def test_mem_enable_cmd():
    cmd = CmdMemEnable(address=100, size=10, mem_id=ExtMemId.MMC_CARD.tag)
    assert cmd.address == 100
    assert cmd.size == 10
    assert cmd.mem_id == ExtMemId.MMC_CARD.tag
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_mem_enable_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdMemEnable.parse(data)


def test_prog_cmd():
    cmd = CmdProg(address=0x1000, mem_id=4, data_word1=0xAABBCCDD, data_word2=0x10000000)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_prog_cmd_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdProg.parse(data)


def test_version_check():
    """Test SB command `CmdVersionCheck`"""
    cmd = CmdVersionCheck(VersionCheckType.NON_SECURE_VERSION, 0x16)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.version == 0x16
    assert cmd.type == VersionCheckType.NON_SECURE_VERSION


def test_version_check_invalid_version():
    class TestVersionCheckType(SpsdkEnum):
        TEST = (2, "TEST")

    with pytest.raises(SPSDKError, match="Invalid version check type"):
        CmdVersionCheck(TestVersionCheckType.TEST, 0x16)


def test_version_check_invalid_parse():
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdVersionCheck.parse(data)


def test_keystore_backup():
    """Test SB command `CmdKeyStoreBackup`"""
    cmd = CmdKeyStoreBackup(1000, ExtMemId.QUAD_SPI0)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.address == 1000
    assert cmd.controller_id == 1


def test_keystore_restore():
    """Test SB command `CmdKeyStoreRestore`"""
    cmd = CmdKeyStoreRestore(1000, ExtMemId.QUAD_SPI0)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.address == 1000
    assert cmd.controller_id == 1


def test_parse_invalid_command_tag():
    with pytest.raises(SPSDKError):
        parse_command(b"\xEE" * 16)


def test_invalid_crc():
    cmd = CmdNop()
    with pytest.raises(SPSDKError):
        cmd.parse(bytes(20))


def test_load_cmd_invalid_crc():
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    valid_data = cmd.export()
    invalid_data = valid_data
    invalid_data = bytearray(invalid_data)
    invalid_data[17:112] = bytearray(112)
    with pytest.raises(SPSDKError):
        cmd.parse(invalid_data)


def test_invalid_cmd_header():
    with pytest.raises(SPSDKError, match="Incorrect command tag"):
        CmdHeader(tag=9999999)


def test_cmd_header_comparison():
    cmd_header = CmdHeader(tag=1)
    cmd = CmdNop()
    assert cmd_header != cmd
