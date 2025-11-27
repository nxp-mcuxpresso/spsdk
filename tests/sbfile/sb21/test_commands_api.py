#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2.1 commands API test module.

This module contains comprehensive unit tests for the SB2.1 (Secure Binary file format 2.1)
command API functionality. It validates the creation, parsing, serialization, and error
handling of various SB2.1 commands used in secure boot file generation.
"""

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


def test_nop_cmd() -> None:
    """Test NOP command creation, export, and parsing functionality.

    Validates that a CmdNop command can be created, exported to binary data,
    and parsed back to an equivalent command object. Verifies the exported
    data has the expected size and matches the command's raw_size property.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdNop()
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_nop_cmd_invalid_parse() -> None:
    """Test that CmdNop.parse() raises an error when given invalid command data.

    This test verifies that the CmdNop parser correctly rejects data from a different
    command type (CmdLoad) by checking that it raises an SPSDKError with the expected
    error message about incorrect header tag.

    :raises SPSDKError: When CmdNop.parse() is given data with wrong header tag.
    """
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdNop.parse(data)


def test_tag_cmd() -> None:
    """Test the CmdTag command functionality.

    This test verifies that the CmdTag command can be properly created, exported to binary data,
    and parsed back from the binary representation while maintaining equality.

    :raises AssertionError: If any of the command operations or comparisons fail.
    """
    cmd = CmdTag()
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_tag_cmd_invalid_parse() -> None:
    """Test that CmdTag.parse raises an error when given invalid data.

    This test verifies that the CmdTag.parse method properly validates the header tag
    and raises an SPSDKError when attempting to parse data that doesn't contain a
    valid tag command header.

    :raises SPSDKError: When the header tag is incorrect for tag command parsing.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdTag.parse(data)


def test_load_cmd() -> None:
    """Test CmdLoad command creation, manipulation, and parsing.

    Validates the CmdLoad command functionality including address and data assignment,
    data modification, export to binary format, and round-trip parsing verification.
    """
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


def test_load_cmd_invalid_address() -> None:
    """Test that CmdLoad raises an error when given an invalid address.

    This test verifies that the CmdLoad command properly validates memory addresses
    and raises an SPSDKError when an address exceeds the valid range for the target
    architecture.

    :raises SPSDKError: When an invalid memory address is assigned to the command.
    """
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFD


def test_load_cmd_invalid_parse() -> None:
    """Test that CmdLoad.parse raises an error when given invalid command data.

    This test verifies that the CmdLoad.parse method properly validates the header tag
    and raises an SPSDKError when attempting to parse data from a different command type.

    :raises SPSDKError: When the header tag is incorrect for CmdLoad parsing.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdLoad.parse(data)


def test_load_cmd_invalid_parse_crc() -> None:
    """Test CmdLoad.parse method with invalid CRC in command header.

    This test verifies that the CmdLoad.parse method properly validates the CRC
    in the command header and raises an appropriate exception when the CRC is
    invalid. It creates a CmdLoad command, exports it, then attempts to parse
    data with corrupted CRC to ensure proper error handling.

    :raises SPSDKError: When invalid CRC is detected in the command header.
    """
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    cmd.export()
    with pytest.raises(SPSDKError, match="Invalid CRC in the command header"):
        CmdLoad.parse(
            data=b"Q\x02\x00\x00d\x00\x00\x00p\x00\x00\x00\x02z\xa7\xfe\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf6\xd1a\x13<\xf5 \x9cP\xb8\x00\x00"
        )


def test_load_cmd_preexisting() -> None:
    """Test parsing of load command with preexisting binary data.

    Verifies that a load command can be correctly parsed from raw binary data
    and that the parsed command contains the expected address and data values.
    The test uses a predefined byte sequence representing a valid load command
    and validates the parsing results.

    :raises AssertionError: If the parsed command is not a CmdLoad instance,
        or if the address or data values don't match expected values.
    """
    data = (
        b"\x1c\x02\x00\x00\n\x00\x00\x00\x10\x00\x00\x00_3<\xd8"
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\xbb\xffT\x0f+r"
    )
    cmd = parse_command(data)
    assert isinstance(cmd, CmdLoad)
    assert cmd.address == 10
    assert cmd.data[:10] == bytes(range(10))


def test_fill_cmd_byte_word() -> None:
    """Test CmdFill command with byte-word pattern functionality.

    Verifies that CmdFill command correctly handles byte-word patterns by testing
    address assignment, pattern generation, data export, and command parsing
    round-trip functionality.
    """
    cmd = CmdFill(address=100, pattern=1, length=4)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x01\x01\x01"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_half_word() -> None:
    """Test CmdFill command with half-word pattern.

    Verifies that CmdFill command correctly handles a half-word (16-bit) pattern
    by testing pattern expansion, data export functionality, and round-trip
    parsing to ensure command integrity.

    :raises AssertionError: If any of the command properties or parsing results don't match expected values.
    """
    cmd = CmdFill(address=100, pattern=258, length=12)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x02\x01\x02"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_whole_word() -> None:
    """Test CmdFill command with whole word pattern.

    Verifies that CmdFill command correctly handles a 4-byte pattern by testing
    address assignment, pattern conversion from integer to bytes, data export
    functionality, and round-trip parsing to ensure command integrity.

    :raises AssertionError: If any of the command properties or parsing results don't match expected values.
    """
    cmd = CmdFill(address=100, pattern=16909060, length=8)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x02\x03\x04"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_length_not_defined() -> None:
    """Test CmdFill command with undefined length parameter.

    Verifies that a CmdFill command can be created without specifying length,
    and that the command maintains proper address and pattern values. Tests
    the export functionality and ensures the exported data has correct size.
    Also validates that the command can be parsed back from exported data
    and remains equivalent to the original command.

    :raises AssertionError: If any of the command properties or operations don't match expected values.
    """
    cmd = CmdFill(address=100, pattern=16909060)
    assert cmd.address == 100
    assert cmd.pattern == b"\x01\x02\x03\x04"

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_fill_cmd_empty_word() -> None:
    """Test creation of CmdFill command with empty word pattern.

    Verifies that a CmdFill command can be successfully created with address 100
    and pattern 0 (empty word), and that the resulting object is not None.
    """
    result = CmdFill(address=100, pattern=0)
    assert result is not None


def test_fill_cmd_incorrect_length() -> None:
    """Test that CmdFill raises SPSDKError when given incorrect length parameter.

    Verifies that creating a CmdFill command with a length value that doesn't
    meet the required constraints (must be divisible by pattern size) properly
    raises an SPSDKError exception.

    :raises SPSDKError: When length parameter is invalid for the given pattern.
    """
    with pytest.raises(SPSDKError):
        CmdFill(address=100, pattern=0, length=9)


def test_fill_cmd_incorrect_word() -> None:
    """Test that CmdFill raises SPSDKError when pattern value exceeds word size limit.

    Verifies that creating a CmdFill command with a pattern value that is too large
    for a word (32-bit) raises the appropriate SPSDKError exception.

    :raises SPSDKError: When pattern value exceeds maximum word size.
    """
    with pytest.raises(SPSDKError):
        CmdFill(address=100, pattern=283678294867452)


def test_fill_cmd_incorrect_address() -> None:
    """Test that CmdFill raises an error when given an incorrect address.

    This test verifies that the CmdFill command properly validates address values
    and raises SPSDKError when an address exceeds the valid range.

    :raises SPSDKError: When address value is out of valid range.
    """
    cmd = CmdFill(address=100, pattern=2)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_fill_cmd_incorrect_parse() -> None:
    """Test that CmdFill.parse raises SPSDKError when given incorrect header tag.

    This test verifies that the CmdFill.parse method properly validates the header tag
    and raises an appropriate SPSDKError when attempting to parse data with an incorrect
    header tag (using CmdNop data instead of CmdFill data).

    :raises SPSDKError: When incorrect header tag is encountered during parsing.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdFill.parse(data)


def test_jump_cmd() -> None:
    """Test CmdJump command creation, serialization, and parsing.

    Validates that a CmdJump command can be properly created with specified
    parameters, exports to correct binary format, and can be parsed back
    to an equivalent command object.

    :raises AssertionError: If any validation check fails during testing.
    """
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


def test_jump_cmd_with_spreg() -> None:
    """Test CmdJump command creation with stack pointer register parameter.

    Verifies that a CmdJump command object is properly initialized when created
    with address, argument, and stack pointer register (spreg) parameters.
    Tests that all properties and internal header fields are set correctly
    and that the string representation contains expected values.
    """
    cmd = CmdJump(address=200, argument=50, spreg=32)
    assert cmd.address == 200
    assert cmd.argument == 50
    assert cmd.spreg == 32
    assert cmd._header.count == 32
    assert cmd._header.flags == 2
    assert cmd._header.address == 200
    assert cmd._header.data == 50
    assert "JUMP: Address=0x000000C8, Argument=0x00000032, SP=0x00000020" in str(cmd)


def test_jump_cmd_invalid() -> None:
    """Test invalid address assignment for jump command.

    Verifies that setting an invalid address (greater than 32-bit range) on a CmdJump
    object raises an SPSDKError with appropriate error message.

    :raises SPSDKError: When address exceeds valid 32-bit range.
    """
    cmd = CmdJump(address=100, argument=10, spreg=None)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_jump_cmd_invalid_parse() -> None:
    """Test that CmdJump.parse raises an error when given invalid data.

    This test verifies that the CmdJump.parse method properly validates input data
    and raises an SPSDKError with the message "Incorrect header tag" when attempting
    to parse data from a different command type (CmdNop in this case).

    :raises SPSDKError: When CmdJump.parse receives data with incorrect header tag.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdJump.parse(data)


def test_call_cmd() -> None:
    """Test CmdCall command creation, serialization, and parsing.

    Validates that a CmdCall command can be properly created with address and argument
    parameters, serialized to binary data, and parsed back to an equivalent command object.
    Tests the command's string representation, export functionality, and round-trip
    serialization/deserialization process.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdCall(address=100, argument=10)
    assert cmd.address == 100
    assert cmd.argument == 10
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_call_cmd_invalid() -> None:
    """Test invalid address assignment for CmdCall command.

    Verifies that setting an invalid address (greater than 32-bit range) on a CmdCall
    command instance raises the appropriate SPSDKError with correct error message.

    :raises SPSDKError: When address exceeds valid 32-bit range.
    """
    cmd = CmdCall(address=100, argument=10)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_call_cmd_invalid_parse() -> None:
    """Test that CmdCall.parse raises an error when given invalid command data.

    This test verifies that the CmdCall.parse method properly validates input data
    and raises an SPSDKError with the message "Incorrect header tag" when attempting
    to parse data from a different command type (CmdNop in this case).

    :raises SPSDKError: When CmdCall.parse receives invalid command data.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Incorrect header tag"):
        CmdCall.parse(data)


def test_erase_cmd() -> None:
    """Test CmdErase command creation, serialization, and parsing.

    Validates that a CmdErase command can be properly created with address, length,
    and flags parameters, serialized to binary data, and parsed back to an
    equivalent command object. Verifies all attributes are preserved through
    the serialization/deserialization cycle.

    :raises AssertionError: If any validation check fails during testing.
    """
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


def test_erase_invalid() -> None:
    """Test invalid address assignment for CmdErase command.

    This test verifies that setting an invalid address (greater than 32-bit range)
    on a CmdErase command instance raises an SPSDKError with appropriate message.

    :raises SPSDKError: When address exceeds valid 32-bit range.
    """
    cmd = CmdErase(address=100, length=10, flags=0)
    with pytest.raises(SPSDKError, match="Incorrect address"):
        cmd.address = 0xFFFFFFFFA


def test_erase_invalid2() -> None:
    """Test parsing CmdErase with invalid NOP command data.

    Verifies that attempting to parse NOP command data as a CmdErase command
    raises an SPSDKError due to invalid header tag mismatch.

    :raises SPSDKError: When parsing data with invalid header tag for CmdErase.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdErase.parse(data)


def test_reset_cmd() -> None:
    """Test the CmdReset command functionality.

    Validates the CmdReset command by testing string representation, data export,
    size verification, and round-trip parsing to ensure command integrity.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdReset()
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_reset_cmd_invalid_parse() -> None:
    """Test that CmdReset.parse() raises SPSDKError when given invalid data.

    This test verifies that the CmdReset.parse() method properly validates input data
    and raises an appropriate exception when attempting to parse data that doesn't
    contain a valid reset command header tag.

    :raises SPSDKError: When CmdReset.parse() receives invalid header tag data.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdReset.parse(data)


def test_mem_enable_cmd() -> None:
    """Test memory enable command functionality.

    Validates the creation, serialization, and parsing of CmdMemEnable command.
    Tests that the command properly stores address, size, and memory ID parameters,
    exports to correct binary format, and can be parsed back to equivalent object.
    """
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


def test_mem_enable_cmd_invalid_parse() -> None:
    """Test that CmdMemEnable.parse raises SPSDKError for invalid header tag.

    This test verifies that attempting to parse data with an incorrect header tag
    (from CmdNop) using CmdMemEnable.parse method properly raises an SPSDKError
    with the expected error message about invalid header tag.

    :raises SPSDKError: When parsing data with invalid header tag.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdMemEnable.parse(data)


def test_prog_cmd() -> None:
    """Test CmdProg command creation, export, and parsing functionality.

    This test verifies that a CmdProg command can be properly created with specific
    parameters, exported to binary data, and then parsed back to an equivalent
    command object. It validates the command's string representation, binary size,
    and round-trip serialization/deserialization.

    :raises AssertionError: If any of the command validation checks fail.
    """
    cmd = CmdProg(address=0x1000, mem_id=4, data_word1=0xAABBCCDD, data_word2=0x10000000)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed


def test_prog_cmd_invalid_parse() -> None:
    """Test that CmdProg.parse raises an error when given invalid data.

    This test verifies that the CmdProg.parse method properly validates input data
    and raises an SPSDKError with "Invalid header tag" message when attempting to
    parse data from a different command type (CmdNop in this case).

    :raises SPSDKError: When CmdProg.parse receives invalid header tag data.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdProg.parse(data)


def test_version_check() -> None:
    """Test SB command `CmdVersionCheck`.

    Verifies the creation, export, parsing, and property access of the CmdVersionCheck
    command for SB2.1 format. Tests command serialization to binary data and
    deserialization back to command object, ensuring data integrity and proper
    attribute handling.

    :raises AssertionError: If any of the command properties or operations don't match expected values.
    """
    cmd = CmdVersionCheck(VersionCheckType.NON_SECURE_VERSION, 0x16)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.version == 0x16
    assert cmd.type == VersionCheckType.NON_SECURE_VERSION


def test_version_check_invalid_version() -> None:
    """Test that CmdVersionCheck raises error for invalid version check type.

    Verifies that creating a CmdVersionCheck instance with an unsupported
    version check type raises SPSDKError with appropriate error message.

    :raises SPSDKError: When invalid version check type is provided.
    """

    class TestVersionCheckType(SpsdkEnum):
        """Test enumeration for version check types in SB2.1 commands.

        This enumeration defines test values used for validating version check
        functionality in Secure Binary 2.1 command testing scenarios.
        """

        TEST = (2, "TEST")

    with pytest.raises(SPSDKError, match="Invalid version check type"):
        CmdVersionCheck(TestVersionCheckType.TEST, 0x16)  # type: ignore[arg-type]


def test_version_check_invalid_parse() -> None:
    """Test that CmdVersionCheck.parse raises SPSDKError for invalid data.

    This test verifies that parsing invalid command data (NOP command data)
    with CmdVersionCheck.parse method properly raises an SPSDKError with
    the expected error message about invalid header tag.

    :raises SPSDKError: When invalid command data is parsed.
    """
    cmd = CmdNop()
    data = cmd.export()
    with pytest.raises(SPSDKError, match="Invalid header tag"):
        CmdVersionCheck.parse(data)


def test_keystore_backup() -> None:
    """Test SB command `CmdKeyStoreBackup`.

    Validates the creation, export, parsing, and property access of the
    CmdKeyStoreBackup command for Secure Binary version 2.1. Tests command
    serialization to binary format, deserialization back to command object,
    and verifies that the parsed command matches the original.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdKeyStoreBackup(1000, ExtMemId.QUAD_SPI0)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.address == 1000
    assert cmd.controller_id == 1


def test_keystore_restore() -> None:
    """Test SB command `CmdKeyStoreRestore`.

    Validates the creation, export, parsing, and property access of the
    CmdKeyStoreRestore command for SB21 secure boot files. Tests command
    serialization to binary format and deserialization back to command object.
    """
    cmd = CmdKeyStoreRestore(1000, ExtMemId.QUAD_SPI0)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16
    assert len(data) == cmd.raw_size

    cmd_parsed = parse_command(data)
    assert cmd == cmd_parsed

    assert cmd.address == 1000
    assert cmd.controller_id == 1


def test_parse_invalid_command_tag() -> None:
    """Test parsing of command with invalid command tag.

    Verifies that parse_command function properly raises SPSDKError
    when attempting to parse a command with an invalid tag (0xee).

    :raises SPSDKError: When invalid command tag is provided to parse_command.
    """
    with pytest.raises(SPSDKError):
        parse_command(b"\xee" * 16)


def test_invalid_crc() -> None:
    """Test that CmdNop.parse() raises SPSDKError when given invalid CRC data.

    This test verifies that the CmdNop command properly validates input data
    and raises an appropriate exception when parsing fails due to invalid CRC.

    :raises SPSDKError: Expected exception when parsing invalid data.
    """
    cmd = CmdNop()
    with pytest.raises(SPSDKError):
        cmd.parse(bytes(20))


def test_load_cmd_invalid_crc() -> None:
    """Test that CmdLoad.parse() raises SPSDKError when CRC is invalid.

    This test verifies that the CmdLoad command properly validates CRC during parsing
    by corrupting the data portion of a valid command and ensuring an SPSDKError is raised.

    :raises SPSDKError: When the corrupted command data is parsed due to invalid CRC.
    """
    cmd = CmdLoad(address=100, data=b"\x00" * 100)
    valid_data = cmd.export()
    invalid_data = valid_data
    invalid_data = bytearray(invalid_data)
    invalid_data[17:112] = bytearray(112)
    with pytest.raises(SPSDKError):
        cmd.parse(invalid_data)


def test_invalid_cmd_header() -> None:
    """Test that CmdHeader raises an error for invalid command tags.

    Verifies that creating a CmdHeader with an invalid tag value raises
    SPSDKError with appropriate error message about incorrect command tag.

    :raises SPSDKError: When an invalid command tag is provided to CmdHeader.
    """
    with pytest.raises(SPSDKError, match="Incorrect command tag"):
        CmdHeader(tag=9999999)


def test_cmd_header_comparison() -> None:
    """Test command header comparison with different object types.

    Verifies that a CmdHeader instance is not equal to a CmdNop instance,
    ensuring proper inequality behavior between different command types.
    """
    cmd_header = CmdHeader(tag=1)
    cmd = CmdNop()
    assert cmd_header != cmd
