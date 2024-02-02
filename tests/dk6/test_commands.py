#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.dk6.commands import *


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (CommandTag.GET_CHIPID.tag, b"\x21\x4a\x04\x94"),
        (
            CommandTag.UNLOCK_ISP.tag,
            b"\x01\x11\x22\x33\x44\x55\x66\x77\x88\x11\x22\x33\x44\x55\x66\x77\x88",
        ),
    ],
)
def test_cmd_response(type, raw_data):
    cmd_response = CmdResponse(type, raw_data)
    assert cmd_response.status == raw_data[0]
    assert "Status" and "Type" in cmd_response.info()


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (CommandTag.GET_CHIPID.tag, b"\x21\x4a\x04\x94"),
        (
            CommandTag.UNLOCK_ISP.tag,
            b"\x01\x11\x22\x33\x44\x55\x66\x77\x88\x11\x22\x33\x44\x55\x66\x77\x88",
        ),
    ],
)
def test_generic_response(type, raw_data):
    generic_response = GenericResponse(type, raw_data)
    assert generic_response.status == raw_data[0]


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.UNLOCK_ISP.tag, b"\x00"),
    ],
)
def test_isp_unlock_response(type, raw_data):
    isp_unlock = IspUnlockResponse(type, raw_data)
    assert isp_unlock.authenticated == True
    assert isp_unlock.status == StatusCode.OK


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.GET_CHIPID.tag, b"\x00\x88\x88\x88\x88\xcc\x00\x00\x14"),
    ],
)
def test_get_chip_id_response(type, raw_data):
    chip_id = GetChipIdResponse(type, raw_data)
    assert chip_id.status == StatusCode.OK
    assert chip_id.chip_id == 0x88888888
    assert chip_id.chip_version == 0x140000CC


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (
            ResponseTag.MEM_GET_INFO.tag,
            b"\x00\x00\x00\x00\x00\x00\x00\xde\x09\x00\x00\x02\x00\x00\x01\x0f\x46\x4c\x41\x53\x48",
        )
    ],
)
def test_mem_get_info_response(type, raw_data):
    get_info = MemGetInfoResponse(type, raw_data)
    assert get_info.status == StatusCode.OK
    assert get_info.access == 15
    assert get_info.base_addr == 0x0
    assert get_info.length == 0x9DE00
    assert "FLASH" in get_info.mem_name
    assert get_info.mem_type == 0x1
    assert get_info.memory_id == 0x0
    assert get_info.sector_size == 0x200
    assert get_info.mem_name == get_info.raw_data[15:].decode("ascii")


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.MEM_OPEN.tag, b"\x00\x00"),
    ],
)
def test_mem_open_response(type, raw_data):
    mem_open = MemOpenResponse(type, raw_data)
    assert mem_open.status == StatusCode.OK
    assert mem_open.handle[0] == 0


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.MEM_READ.tag, b"\x00\xff\xff\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_mem_read_response(type, raw_data):
    mem_read = MemReadResponse(type, raw_data)
    assert mem_read.status == StatusCode.OK
    assert mem_read.data == raw_data[1:]


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.MEM_WRITE.tag, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ],
)
def test_mem_write_response(type, raw_data):
    mem_write = MemWriteResponse(type, raw_data)
    assert mem_write.status == StatusCode.OK


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.MEM_ERASE.tag, b"\x00\x00\x09\x43\x00\x12\xa7\xd0\x54"),
    ],
)
def test_mem_erase_response(type, raw_data):
    mem_erase = MemEraseResponse(type, raw_data)
    assert mem_erase.status == StatusCode.OK


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.MEM_BLANK_CHECK.tag, b"\x00\x00\x09\x45\x00\x44\xfd\x77\xd2"),
    ],
)
def test_mem_check_response(type, raw_data):
    mem_check = MemBlankCheckResponse(type, raw_data)
    assert mem_check.status == StatusCode.OK


@pytest.mark.parametrize(
    "type,raw_data",
    [
        (ResponseTag.MEM_CLOSE.tag, b"\x00"),
    ],
)
def test_mem_close_response(type, raw_data):
    mem_close = MemCloseResponse(type, raw_data)
    assert mem_close.status == StatusCode.OK
