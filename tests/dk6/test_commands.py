#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 commands testing module.

This module contains comprehensive test cases for DK6 protocol command and response
handling functionality. It validates the proper creation, serialization, and
deserialization of various DK6 commands and their corresponding responses including
ISP unlock, chip identification, and memory operations.
"""

import pytest

from spsdk.dk6.commands import (
    CmdResponse,
    CommandTag,
    GenericResponse,
    GetChipIdResponse,
    IspUnlockResponse,
    MemBlankCheckResponse,
    MemCloseResponse,
    MemEraseResponse,
    MemGetInfoResponse,
    MemOpenResponse,
    MemReadResponse,
    MemWriteResponse,
    ResponseTag,
    StatusCode,
)


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (CommandTag.GET_CHIPID.tag, b"\x21\x4a\x04\x94"),
        (
            CommandTag.UNLOCK_ISP.tag,
            b"\x01\x11\x22\x33\x44\x55\x66\x77\x88\x11\x22\x33\x44\x55\x66\x77\x88",
        ),
    ],
)
def test_cmd_response(cmd_type: int, raw_data: bytes) -> None:
    """Test command response functionality.

    Validates that a CmdResponse object is properly initialized with the given
    type and raw data, and verifies that the status is correctly extracted
    from the first byte of raw data and that required fields are present
    in the info output.

    :param cmd_type: Command response type identifier.
    :param raw_data: Raw response data bytes where first byte represents status.
    """
    cmd_response = CmdResponse(cmd_type, raw_data)
    assert cmd_response.status == raw_data[0]
    assert "Status" in cmd_response.info() and "Type" in cmd_response.info()


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (CommandTag.GET_CHIPID.tag, b"\x21\x4a\x04\x94"),
        (
            CommandTag.UNLOCK_ISP.tag,
            b"\x01\x11\x22\x33\x44\x55\x66\x77\x88\x11\x22\x33\x44\x55\x66\x77\x88",
        ),
    ],
)
def test_generic_response(cmd_type: int, raw_data: bytes) -> None:
    """Test generic response creation and status validation.

    Validates that a GenericResponse object can be created with the provided
    type and raw data, and that the status property correctly returns the
    first byte of the raw data.

    :param cmd_type: Response type identifier for the generic response.
    :param raw_data: Raw byte data containing the response payload.
    """
    generic_response = GenericResponse(cmd_type, raw_data)
    assert generic_response.status == raw_data[0]


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.UNLOCK_ISP.tag, b"\x00"),
    ],
)
def test_isp_unlock_response(cmd_type: int, raw_data: bytes) -> None:
    """Test ISP unlock response functionality.

    Verifies that an IspUnlockResponse object is properly created with the given
    type and raw data, and validates that the response indicates successful
    authentication with OK status.

    :param cmd_type: The type identifier for the ISP unlock response.
    :param raw_data: Raw byte data containing the unlock response payload.
    """
    isp_unlock = IspUnlockResponse(cmd_type, raw_data)
    assert isp_unlock.authenticated
    assert isp_unlock.status == StatusCode.OK


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.GET_CHIPID.tag, b"\x00\x88\x88\x88\x88\xcc\x00\x00\x14"),
    ],
)
def test_get_chip_id_response(cmd_type: int, raw_data: bytes) -> None:
    """Test GetChipIdResponse command parsing and validation.

    Verifies that the GetChipIdResponse object correctly parses the provided
    raw data and extracts the expected chip ID and version values.

    :param cmd_type: Response type identifier for the GetChipIdResponse command.
    :param raw_data: Raw byte data containing the chip ID response payload.
    """
    chip_id = GetChipIdResponse(cmd_type, raw_data)
    assert chip_id.status == StatusCode.OK
    assert chip_id.chip_id == 0x88888888
    assert chip_id.chip_version == 0x140000CC


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (
            ResponseTag.MEM_GET_INFO.tag,
            b"\x00\x00\x00\x00\x00\x00\x00\xde\x09\x00\x00\x02\x00\x00\x01\x0f\x46\x4c\x41\x53\x48",
        )
    ],
)
def test_mem_get_info_response(cmd_type: int, raw_data: bytes) -> None:
    """Test MemGetInfoResponse object creation and attribute validation.

    Validates that a MemGetInfoResponse object is correctly initialized with the provided
    type and raw data, and verifies all expected attributes have correct values including
    status, access permissions, memory properties, and decoded memory name.

    :param cmd_type: Memory type identifier for the response object.
    :param raw_data: Raw binary data containing memory information to be parsed.
    """
    get_info = MemGetInfoResponse(cmd_type, raw_data)
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
    "cmd_type,raw_data",
    [
        (ResponseTag.MEM_OPEN.tag, b"\x00\x00"),
    ],
)
def test_mem_open_response(cmd_type: int, raw_data: bytes) -> None:
    """Test memory open response functionality.

    Validates that a MemOpenResponse object is correctly initialized with the provided
    type and raw data, and verifies that the status is OK and the first handle byte is zero.

    :param cmd_type: The type identifier for the memory open response.
    :param raw_data: The raw byte data for the memory open response.
    """
    mem_open = MemOpenResponse(cmd_type, raw_data)
    assert mem_open.status == StatusCode.OK
    assert mem_open.handle[0] == 0


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.MEM_READ.tag, b"\x00\xff\xff\xff\xff\xff\xff\xff\xff"),
    ],
)
def test_mem_read_response(cmd_type: int, raw_data: bytes) -> None:
    """Test memory read response functionality.

    Verifies that a MemReadResponse object is correctly initialized with the given
    type and raw data, and that the status is OK while data excludes the first byte.

    :param cmd_type: The response type identifier for the memory read operation.
    :param raw_data: Raw bytes data received from the memory read response.
    """
    mem_read = MemReadResponse(cmd_type, raw_data)
    assert mem_read.status == StatusCode.OK
    assert mem_read.data == raw_data[1:]


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.MEM_WRITE.tag, b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ],
)
def test_mem_write_response(cmd_type: int, raw_data: bytes) -> None:
    """Test memory write response functionality.

    Verifies that a MemWriteResponse object can be created with the given type
    and raw data, and that its status is correctly set to StatusCode.OK.

    :param cmd_type: The type identifier for the memory write response.
    :param raw_data: The raw byte data for the memory write response.
    """
    mem_write = MemWriteResponse(cmd_type, raw_data)
    assert mem_write.status == StatusCode.OK


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.MEM_ERASE.tag, b"\x00\x00\x09\x43\x00\x12\xa7\xd0\x54"),
    ],
)
def test_mem_erase_response(cmd_type: int, raw_data: bytes) -> None:
    """Test memory erase response functionality.

    Validates that a MemEraseResponse object can be properly created with the given
    type and raw data parameters, and verifies that the response status is OK.

    :param cmd_type: The type identifier for the memory erase response.
    :param raw_data: Raw byte data for the memory erase response.
    """
    mem_erase = MemEraseResponse(cmd_type, raw_data)
    assert mem_erase.status == StatusCode.OK


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.MEM_BLANK_CHECK.tag, b"\x00\x00\x09\x45\x00\x44\xfd\x77\xd2"),
    ],
)
def test_mem_check_response(cmd_type: int, raw_data: bytes) -> None:
    """Test memory blank check response functionality.

    Verifies that a MemBlankCheckResponse object can be properly created
    with the given type and raw data, and that its status is set to OK.

    :param cmd_type: The response type identifier.
    :param raw_data: Raw byte data for the memory check response.
    """
    mem_check = MemBlankCheckResponse(cmd_type, raw_data)
    assert mem_check.status == StatusCode.OK


@pytest.mark.parametrize(
    "cmd_type,raw_data",
    [
        (ResponseTag.MEM_CLOSE.tag, b"\x00"),
    ],
)
def test_mem_close_response(cmd_type: int, raw_data: bytes) -> None:
    """Test MemCloseResponse initialization and status verification.

    Verifies that a MemCloseResponse object can be properly initialized with
    the given type and raw data, and that its status is set to OK.

    :param cmd_type: The response type identifier.
    :param raw_data: Raw binary data for the response.
    """
    mem_close = MemCloseResponse(cmd_type, raw_data)
    assert mem_close.status == StatusCode.OK
