#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK MBoot commands test suite.

This module contains comprehensive tests for the MBoot protocol commands and responses,
including command headers, packets, and various response types used in secure
provisioning and device communication.
"""

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


def test_cmd_header_class() -> None:
    """Test CmdHeader class functionality.

    Validates the CmdHeader class constructor, property access, serialization,
    deserialization, equality comparison, and string representation methods.
    The test ensures proper handling of command tag, flags, reserved field,
    and parameter count values.
    """
    cmd_header = CmdHeader(CommandTag.FLASH_ERASE_ALL.tag, 0, 2, 3)
    assert cmd_header.tag == CommandTag.FLASH_ERASE_ALL.tag
    assert cmd_header.flags == 0
    assert cmd_header.reserved == 2
    assert cmd_header.params_count == 3
    assert cmd_header.export() == b"\x01\x00\x02\x03"
    assert cmd_header == CmdHeader.parse(b"\x01\x00\x02\x03")
    assert cmd_header != CmdHeader.parse(b"\x01\x00\x02\x05")
    assert str(cmd_header)
    assert repr(cmd_header)


def test_cmd_packet_class() -> None:
    """Test CmdPacket class functionality and methods.

    Validates CmdPacket creation, header generation, parameter parsing,
    data export, equality comparison, and string representations.

    :raises AssertionError: If any of the CmdPacket functionality tests fail.
    """
    cmd = CmdPacket(CommandTag.FLASH_ERASE_ALL, 0, 0, data=b"\x00\x00\x00\x00\x00")
    assert cmd.header == CmdHeader(CommandTag.FLASH_ERASE_ALL.tag, 0, 0, 3)
    assert cmd.params == [0, 0, 0]
    assert cmd.export(False) == b"\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert cmd != CmdPacket(CommandTag.WRITE_MEMORY, 0, 0)
    assert str(cmd)
    assert repr(cmd)


def test_cmd_response_class() -> None:
    """Test CmdResponse class functionality and parsing.

    Validates that parse_cmd_response correctly creates CmdResponse objects
    with proper header parsing, raw data extraction, and object comparison.
    Tests string representations and ensures different responses are not equal.
    """
    response = parse_cmd_response(b"\x01\x00\x00\x01\x00\x00\x00\x00")
    assert isinstance(response, CmdResponse)
    assert response.header == CmdHeader(CommandTag.FLASH_ERASE_ALL.tag, 0, 0, 1)
    assert response.raw_data == b"\x00\x00\x00\x00"
    assert response != parse_cmd_response(b"\xa0\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert str(response)
    assert repr(response)


def test_generic_response_class() -> None:
    """Test parsing of generic response command.

    This test verifies that a raw byte response is correctly parsed into a
    GenericResponse object with proper header, status, and command tag values.
    The test uses a sample byte sequence representing a flash erase all command
    response and validates all parsed attributes.

    :raises AssertionError: If any of the parsed response attributes don't match expected values.
    """
    response = parse_cmd_response(b"\xa0\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert isinstance(response, GenericResponse)
    assert response.header == CmdHeader(ResponseTag.GENERIC.tag, 0, 0, 2)
    assert response.status == 0
    assert response.cmd_tag == CommandTag.FLASH_ERASE_ALL
    assert str(response)


def test_read_memory_response_class() -> None:
    """Test ReadMemoryResponse class parsing and validation.

    Verifies that a raw byte response is correctly parsed into a ReadMemoryResponse
    object and validates all its properties including header, status, and length.
    """
    response = parse_cmd_response(b"\xa3\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert isinstance(response, ReadMemoryResponse)
    assert response.header == CmdHeader(ResponseTag.READ_MEMORY.tag, 0, 0, 2)
    assert response.status == 0
    assert response.length == 1
    assert str(response)


def test_get_property_response_class() -> None:
    """Test parsing of GetPropertyResponse from raw command response bytes.

    Verifies that the parse_cmd_response function correctly parses a raw byte sequence
    into a GetPropertyResponse object and validates all its attributes including header,
    status, and property values.

    :raises AssertionError: If any of the response attributes don't match expected values.
    """
    response = parse_cmd_response(b"\xa7\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00")
    assert isinstance(response, GetPropertyResponse)
    assert response.header == CmdHeader(ResponseTag.GET_PROPERTY.tag, 0, 0, 2)
    assert response.status == 0
    assert response.values == [1]
    assert str(response)


def test_flash_read_once_response_class() -> None:
    """Test FlashReadOnceResponse class parsing and validation.

    Verifies that a binary response is correctly parsed into a FlashReadOnceResponse
    object and validates all its attributes including header, status, length, and data.
    """
    response = parse_cmd_response(
        b"\xaf\x00\x00\x03\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00"
    )
    assert isinstance(response, FlashReadOnceResponse)
    assert response.header == CmdHeader(ResponseTag.FLASH_READ_ONCE.tag, 0, 0, 3)
    assert response.status == 0
    assert response.length == 4
    assert response.data == b"\x01\x00\x00\x00"
    assert str(response)


def test_flash_read_resource_response_class() -> None:
    """Test FlashReadResourceResponse class parsing and validation.

    Verifies that a raw byte response is correctly parsed into a FlashReadResourceResponse
    object and validates all its properties including header, status, and length fields.
    """
    response = parse_cmd_response(b"\xb0\x00\x00\x02\x00\x00\x00\x00\x04\x00\x00\x00")
    assert isinstance(response, FlashReadResourceResponse)
    assert response.header == CmdHeader(ResponseTag.FLASH_READ_RESOURCE.tag, 0, 0, 2)
    assert response.status == 0
    assert response.length == 4
    assert str(response)


def test_tp_hsm_gen_key_response_class() -> None:
    """Test Trust Provisioning HSM generate key response class parsing.

    This test verifies that a binary response for HSM key generation command
    is correctly parsed into a TrustProvisioningResponse object with proper
    header, status, and parameter values.
    """
    response = parse_cmd_response(
        b"\xb6\x00\x00\x03\x00\x00\x00\x00\x30\x00\x00\x00\x40\x00\x00\x00"
    )
    assert isinstance(response, TrustProvisioningResponse)
    assert response.header == CmdHeader(tag=0xB6, flags=0x00, reserved=0, params_count=3)
    assert response.status == 0
    assert response.values == [48, 64]
    assert str(response)
