#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from spsdk.mboot.commands import (
    CmdHeader,
    CmdPacket,
    CmdResponse,
    CommandTag,
    FlashReadOnceResponse,
    FlashReadResourceResponse,
    GenericResponse,
    GetPropertyResponse,
    ReadMemoryResponse,
    ResponseTag,
    TrustProvisioningResponse,
    parse_cmd_response,
)


def test_cmd_header_class():
    cmd_header = CmdHeader(CommandTag.FLASH_ERASE_ALL.tag, 0, 2, 3)
    assert cmd_header.tag == CommandTag.FLASH_ERASE_ALL.tag
    assert cmd_header.flags == 0
    assert cmd_header.reserved == 2
    assert cmd_header.params_count == 3
    assert cmd_header.to_bytes() == b"\x01\x00\x02\x03"
    assert cmd_header == CmdHeader.from_bytes(b"\x01\x00\x02\x03")
    assert cmd_header != CmdHeader.from_bytes(b"\x01\x00\x02\x05")
    assert str(cmd_header)
    assert repr(cmd_header)


def test_cmd_packet_class():
    cmd = CmdPacket(CommandTag.FLASH_ERASE_ALL, 0, 0, data=b"\x00\x00\x00\x00\x00")
    assert cmd.header == CmdHeader(CommandTag.FLASH_ERASE_ALL.tag, 0, 0, 3)
    assert cmd.params == [0, 0, 0]
    assert (
        cmd.to_bytes(False) == b"\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    assert cmd != CmdPacket(CommandTag.WRITE_MEMORY, 0, 0)
    assert str(cmd)
    assert repr(cmd)


def test_cmd_response_class():
    response = parse_cmd_response(b"\x01\x00\x00\x01\x00\x00\x00\x00")
    assert isinstance(response, CmdResponse)
    assert response.header == CmdHeader(CommandTag.FLASH_ERASE_ALL.tag, 0, 0, 1)
    assert response.raw_data == b"\x00\x00\x00\x00"
    assert response != parse_cmd_response(b"\xA0\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert str(response)
    assert repr(response)


def test_generic_response_class():
    response = parse_cmd_response(b"\xA0\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert isinstance(response, GenericResponse)
    assert response.header == CmdHeader(ResponseTag.GENERIC.tag, 0, 0, 2)
    assert response.status == 0
    assert response.cmd_tag == CommandTag.FLASH_ERASE_ALL
    assert str(response)


def test_read_memory_response_class():
    response = parse_cmd_response(b"\xA3\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert isinstance(response, ReadMemoryResponse)
    assert response.header == CmdHeader(ResponseTag.READ_MEMORY.tag, 0, 0, 2)
    assert response.status == 0
    assert response.length == 1
    assert str(response)


def test_get_property_response_class():
    response = parse_cmd_response(b"\xA7\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert isinstance(response, GetPropertyResponse)
    assert response.header == CmdHeader(ResponseTag.GET_PROPERTY.tag, 0, 0, 2)
    assert response.status == 0
    assert response.values == [1]
    assert str(response)


def test_flash_read_once_response_class():
    response = parse_cmd_response(
        b"\xAF\x00\x00\x03\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00"
    )
    assert isinstance(response, FlashReadOnceResponse)
    assert response.header == CmdHeader(ResponseTag.FLASH_READ_ONCE.tag, 0, 0, 3)
    assert response.status == 0
    assert response.length == 4
    assert response.data == b"\x01\x00\x00\x00"
    assert str(response)


def test_flash_read_resource_response_class():
    response = parse_cmd_response(b"\xB0\x00\x00\x02\x00\x00\x00\x00\x04\x00\x00\x00")
    assert isinstance(response, FlashReadResourceResponse)
    assert response.header == CmdHeader(ResponseTag.FLASH_READ_RESOURCE.tag, 0, 0, 2)
    assert response.status == 0
    assert response.length == 4
    assert str(response)


def test_tp_hsm_gen_key_response_class():
    response = parse_cmd_response(
        b"\xb6\x00\x00\x03\x00\x00\x00\x00\x30\x00\x00\x00\x40\x00\x00\x00"
    )
    assert isinstance(response, TrustProvisioningResponse)
    assert response.header == CmdHeader(tag=0xB6, flags=0x00, reserved=0, params_count=3)
    assert response.status == 0
    assert response.values == [48, 64]
    assert str(response)
