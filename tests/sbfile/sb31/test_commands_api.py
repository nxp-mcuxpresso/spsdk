#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SB3.1 commands API test suite.

This module contains comprehensive tests for the SB3.1 (Secure Binary 3.1) command
API functionality, validating command creation, parsing, and error handling across
all supported command types including memory operations, security features, and
configuration management.
"""


import os
from typing import Optional

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31.commands import (
    BaseCmd,
    CmdCall,
    CmdCheckLifecycle,
    CmdConfigureMemory,
    CmdCopy,
    CmdErase,
    CmdExecute,
    CmdFillMemory,
    CmdFwVersionCheck,
    CmdLoad,
    CmdLoadBase,
    CmdLoadCmac,
    CmdLoadHashLocking,
    CmdLoadKeyBlob,
    CmdProgFuses,
    CmdProgIfr,
    CmdSectionHeader,
    CmdWriteIfr,
    parse_command,
)
from spsdk.sbfile.sb31.constants import EnumCmdTag
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision


def test_cmd_erase() -> None:
    """Test CmdErase command functionality.

    Validates that CmdErase command properly handles address, length, and memory_id
    parameters, maintains correct values after initialization, exports to expected
    data size, and can be parsed back to equivalent command object.
    """
    cmd = CmdErase(address=100, length=0xFF, memory_id=10)
    assert cmd.address == 100
    assert cmd.length == 0xFF
    assert cmd.memory_id == 10
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 32

    cmd_parsed = CmdErase.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_erase_cmd_tag() -> None:
    """Test CmdErase command parsing with invalid command tag.

    This test verifies that parsing a CmdErase command with an incorrect
    command tag raises the appropriate SPSDKError exception.

    :raises SPSDKError: When parsing command data with invalid tag.
    """
    cmd = CmdErase(address=0, length=0, memory_id=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdErase.parse(data=data)


def test_parse_cmd_erase_invalid_padding() -> None:
    """Test parsing of CmdErase command with invalid padding.

    This test verifies that the CmdErase.parse() method correctly raises an
    SPSDKError when attempting to parse command data that contains invalid
    padding bytes.

    :raises SPSDKError: When the command data contains invalid padding.
    """
    cmd = CmdErase(address=100, length=0xFF)
    data = b"U\xaa\xaaUd\x00\x00\x00\xff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"  # pylint: disable=line-too-long
    with pytest.raises(SPSDKError, match="Invalid padding"):
        cmd.parse(data)


def test_cmd_load() -> None:
    """Test CmdLoad command functionality.

    Validates that CmdLoad command properly handles address, length, memory_id,
    and info values. Tests the complete workflow including command creation,
    data export, size verification, and parsing back from exported data.

    :raises AssertionError: If any of the command properties don't match expected values.
    """
    cmd = CmdLoad(address=100, data=bytes(range(10)), memory_id=1)
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.memory_id == 1
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 48

    cmd_parsed = CmdLoad.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_load_cmd_tag() -> None:
    """Test CmdLoad command parsing with invalid command tag.

    Verifies that parsing a CmdLoad command with an incorrect CMD_TAG raises
    an SPSDKError exception. The test creates a valid CmdLoad command, modifies
    its tag to an invalid value (CALL), exports it, and attempts to parse it back.

    :raises SPSDKError: When parsing command data with invalid tag.
    """
    cmd = CmdLoad(address=0, data=bytes(4), memory_id=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdLoad.parse(data=data)


def test_cmd_execute() -> None:
    """Test address, info value, size after export and parsing of CmdExecute command.

    This test verifies that the CmdExecute command correctly handles address assignment,
    string representation, data export with proper size, and bidirectional parsing
    ensuring the original and parsed commands are equivalent.
    """
    cmd = CmdExecute(address=100)
    assert cmd.address == 100
    assert str(cmd)

    data = cmd.export()
    assert len(data) == BaseCmd.SIZE

    cmd_parsed = CmdExecute.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_execute_cmd_tag() -> None:
    """Test that CmdExecute.parse() raises SPSDKError when parsing data with invalid command tag.

    The test creates a CmdExecute command, modifies its CMD_TAG to an invalid value (CALL),
    exports the data, and verifies that parsing this corrupted data raises an SPSDKError.

    :raises SPSDKError: When parsing data with invalid command tag.
    """
    cmd = CmdExecute(address=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdExecute.parse(data)


def test_cmd_call() -> None:
    """Test the CmdCall command functionality.

    Validates that the CmdCall command correctly handles address assignment,
    string representation, data export with proper size, and bidirectional
    parsing to ensure data integrity.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdCall(address=100)
    assert cmd.address == 100
    assert str(cmd)

    data = cmd.export()
    assert len(data) == BaseCmd.SIZE

    cmd_parsed = CmdCall.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_call_cmd_tag() -> None:
    """Test CmdCall command parsing with invalid command tag.

    This test verifies that parsing a CmdCall command with an incorrect CMD_TAG
    raises an SPSDKError. It creates a CmdCall with ERASE tag instead of the
    expected tag and attempts to parse the exported data.

    :raises SPSDKError: When parsing CmdCall data with invalid command tag.
    """
    cmd = CmdCall(address=0)
    cmd.CMD_TAG = EnumCmdTag.ERASE
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdCall.parse(data=data)


def test_program_cmd_progfuses() -> None:
    """Test the CmdProgFuses command functionality.

    Validates that the CmdProgFuses command correctly handles address and data
    parameters, maintains proper length calculation, supports string representation,
    exports to correct binary format, and can be parsed back from exported data.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdProgFuses(address=100, data=bytes(12))
    assert cmd.address == 100
    assert cmd.length == 3
    assert str(cmd)

    data = cmd.export()
    assert len(data) == BaseCmd.SIZE + 4 * 4

    cmd_parsed = CmdProgFuses.parse(data=data)
    assert cmd == cmd_parsed


def test_cmd_progifr() -> None:
    """Test the CmdProgIfr command functionality.

    Validates that the CmdProgIfr command correctly handles address and data properties,
    exports to binary format with expected size, and can be parsed back to an equivalent
    command object.
    """
    cmd = CmdProgIfr(address=100, data=bytes([0] * 100))
    assert cmd.address == 100
    assert cmd.data == bytes([0] * 100)
    assert str(cmd)

    data = cmd.export()
    assert len(data) == BaseCmd.SIZE + len(cmd.data) + 12

    cmd_parsed = CmdProgIfr.parse(data=data)
    assert cmd == cmd_parsed


def test_cmd_loadcmac() -> None:
    """Test CmdLoadCmac command functionality.

    Validates that CmdLoadCmac command properly handles address, length, memory_id,
    and info values. Tests export functionality and verifies that parsing exported
    data recreates an equivalent command object.
    """
    cmd = CmdLoadCmac(address=100, data=bytes(range(10)), memory_id=0)
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.memory_id == 0
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 48

    cmd_parsed = CmdLoadCmac.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_loadcmac_cmd_tag() -> None:
    """Test CmdLoadCmac command parsing with invalid command tag.

    This test verifies that parsing a CmdLoadCmac command with an incorrect
    command tag raises the expected SPSDKError exception. The test creates
    a valid CmdLoadCmac command, corrupts its tag, exports it, and then
    attempts to parse the corrupted data.

    :raises SPSDKError: Expected exception when parsing command with invalid tag.
    """
    cmd = CmdLoadCmac(address=0, data=bytes(10), memory_id=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdLoadCmac.parse(data=data)


def test_cmd_copy() -> None:
    """Test CmdCopy command functionality.

    Validates that CmdCopy command properly handles address, length, destination_address,
    memory_id_from, memory_id_to parameters, info value, export size alignment,
    and round-trip parsing consistency.
    """
    cmd = CmdCopy(
        address=100, length=10, destination_address=20, memory_id_from=30, memory_id_to=40
    )
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.destination_address == 20
    assert cmd.memory_id_from == 30
    assert cmd.memory_id_to == 40
    assert str(cmd)

    data = cmd.export()
    assert len(data) % 16 == 0

    cmd_parsed = CmdCopy.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_copy_cmd_tag() -> None:
    """Test CmdCopy command parsing with invalid command tag.

    This test verifies that parsing fails correctly when a CmdCopy command has an invalid
    CMD_TAG value. It creates a CmdCopy command, modifies its tag to an incompatible value
    (CALL), exports the data, and ensures that parsing with CmdLoadCmac raises an SPSDKError.

    :raises SPSDKError: Expected exception when parsing invalid command data.
    """
    cmd = CmdCopy(address=100, length=0, destination_address=0, memory_id_from=0, memory_id_to=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdLoadCmac.parse(data=data)


def test_cmd_loadhashlocking() -> None:
    """Test CmdLoadHashLocking command functionality.

    Validates that CmdLoadHashLocking command properly handles address, length,
    memory_id properties and ensures correct export/parse roundtrip behavior.
    The test verifies command creation, property access, string representation,
    export data size, and parsing consistency.
    """
    cmd = CmdLoadHashLocking(address=100, data=bytes(range(10)), memory_id=5)
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.memory_id == 5
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 48 + 64

    cmd_parsed = CmdLoadHashLocking.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_loadhashlocking_cmd_tag() -> None:
    """Test parsing of CmdLoadHashLocking command with invalid tag.

    This test verifies that parsing a CmdLoadHashLocking command with an incorrect
    CMD_TAG raises an SPSDKError exception. The test creates a valid command,
    modifies its tag to an invalid value (CALL), exports it, and then attempts
    to parse the corrupted data.

    :raises SPSDKError: When parsing command data with invalid tag.
    """
    cmd = CmdLoadHashLocking(address=0, data=bytes(10), memory_id=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdLoadHashLocking.parse(data=data)


def test_cmd_loadkeyblob() -> None:
    """Test CmdLoadKeyBlob command functionality.

    Validates the creation, export, and parsing of CmdLoadKeyBlob command including
    offset, length, key_wrap_id, data properties, and ensures proper serialization
    and deserialization with correct data alignment.
    """
    cmd = CmdLoadKeyBlob(
        offset=100,
        key_wrap_id=CmdLoadKeyBlob.get_key_id(
            FamilyRevision("lpc55s3x"), CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK
        ),
        data=10 * b"x",
    )
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.key_wrap_id == 17
    assert str(cmd)

    data = cmd.export()
    assert len(data) % 16 == 0

    cmd_parsed = CmdLoadKeyBlob.parse(data=data)
    assert cmd == cmd_parsed
    assert cmd.data == cmd_parsed.data == 10 * b"x"


def test_cmd_loadkeyblob_v2() -> None:
    """Test CmdLoadKeyBlob V2 command functionality.

    Validates the offset, length, key_wrap, data info value, size after export
    and parsing operations of CmdLoadKeyBlob V2 command. Tests command creation,
    property access, export functionality, and round-trip parsing to ensure
    data integrity.
    """
    cmd = CmdLoadKeyBlob(
        offset=100, key_wrap_id=CmdLoadKeyBlob._KeyWrapsV2.NXP_CUST_KEK_EXT_SK.value, data=10 * b"x"
    )
    assert cmd.address == 100
    assert cmd.length == 10
    assert cmd.key_wrap_id == 19
    assert str(cmd)

    data = cmd.export()
    assert len(data) % 16 == 0

    cmd_parsed = CmdLoadKeyBlob.parse(data=data)
    assert cmd == cmd_parsed
    assert cmd.data == cmd_parsed.data == 10 * b"x"


def test_parse_invalid_cmd_loadkeyblob_cmd_tag() -> None:
    """Test CmdLoadKeyBlob command parsing with invalid command tag.

    This test verifies that parsing fails correctly when a CmdLoadKeyBlob object
    has its command tag modified to an invalid value before export and subsequent
    parsing by a different command class.

    :raises SPSDKError: Expected exception when parsing data with mismatched command tag.
    """
    cmd = CmdLoadKeyBlob(
        offset=100, key_wrap_id=CmdLoadKeyBlob._KeyWraps.NXP_CUST_KEK_EXT_SK.value, data=bytes(10)
    )
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdErase.parse(data=data)


def test_cmd_configurememory() -> None:
    """Test CmdConfigureMemory command functionality.

    Validates that CmdConfigureMemory command correctly handles address and memory_id
    parameters, exports to proper binary format, and can be parsed back to equivalent
    command object.

    :raises AssertionError: If any validation check fails during testing.
    """
    cmd = CmdConfigureMemory(address=100, memory_id=10)
    assert cmd.address == 100
    assert cmd.memory_id == 10
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16

    cmd_parsed = CmdConfigureMemory.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_configurememory_cmd_tag() -> None:
    """Test that CmdConfigureMemory.parse() raises SPSDKError when given data with invalid command tag.

    This test verifies that the parse method properly validates the command tag field
    and rejects data that contains an incorrect tag value for the CmdConfigureMemory command.

    :raises SPSDKError: When parsing data with invalid command tag.
    """
    cmd = CmdConfigureMemory(address=0, memory_id=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdConfigureMemory.parse(data=data)


def test_cmd_fillmemory() -> None:
    """Test CmdFillMemory command functionality.

    Validates that CmdFillMemory command correctly handles address, length, and pattern
    parameters, exports to proper binary format, and can be parsed back to equivalent
    command object.
    """
    cmd = CmdFillMemory(address=100, length=100, pattern=0xFF1111FF)
    assert cmd.address == 100
    assert cmd.length == 100
    assert cmd.pattern == 0xFF1111FF
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 32

    cmd_parsed = CmdFillMemory.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_fillmemory_cmd_tag() -> None:
    """Test invalid command tag parsing for CmdFillMemory.

    This test verifies that the parse method properly validates the command tag
    and raises an appropriate exception when attempting to parse data that was
    exported with an incorrect CMD_TAG value.

    :raises SPSDKError: When parsing data with invalid command tag (expected behavior).
    """
    cmd = CmdFillMemory(address=0, length=0, pattern=0)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdFillMemory.parse(data=data)


def test_cmd_fwversioncheck() -> None:
    """Test firmware version check command functionality.

    Validates that CmdFwVersionCheck command properly handles value and counter_id
    parameters, maintains data integrity through export/parse cycle, and produces
    correctly sized output data aligned to 16-byte boundaries.
    """
    cmd = CmdFwVersionCheck(value=100, counter_id=CmdFwVersionCheck.CounterID.SECURE)
    assert cmd.value == 100
    assert cmd.counter_id == 2
    assert str(cmd)

    data = cmd.export()
    assert len(data) % 16 == 0

    cmd_parsed = CmdFwVersionCheck.parse(data=data)
    assert cmd == cmd_parsed


def test_parse_invalid_cmd_fwversioncheck_cmd_tag() -> None:
    """Test CmdFwVersionCheck command parsing with invalid command tag.

    This test verifies that the CmdFwVersionCheck.parse() method properly raises
    an SPSDKError when attempting to parse data with an incorrect command tag.
    The test creates a valid CmdFwVersionCheck command, corrupts its tag, exports
    the data, and confirms that parsing fails as expected.

    :raises SPSDKError: Expected exception when parsing invalid command data.
    """
    cmd = CmdFwVersionCheck(value=100, counter_id=CmdFwVersionCheck.CounterID.SECURE)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdFwVersionCheck.parse(data=data)


def test_section_header_cmd() -> None:
    """Test CmdSectionHeader command functionality.

    Validates section UID, section type, length properties, data export size,
    and round-trip parsing to ensure command serialization and deserialization
    work correctly.
    """
    cmd = CmdSectionHeader(section_uid=10, section_type=10, length=100)
    assert cmd.section_uid == 10
    assert cmd.section_type == 10
    assert cmd.length == 100

    data = cmd.export()
    assert len(data) == BaseCmd.SIZE

    cmd_parsed = CmdSectionHeader.parse(data=data)
    assert cmd == cmd_parsed


def test_section_cmd_header_basic() -> None:
    """Test basic functionality of CmdSectionHeader inequality comparison.

    Verifies that two CmdSectionHeader instances with different length values
    are correctly identified as not equal when compared using the != operator.
    This test ensures the proper implementation of the inequality comparison
    for section header commands in the SB3.1 file format.
    """
    section_header = CmdSectionHeader(length=10)
    section_header2 = CmdSectionHeader(length=500)

    assert section_header != section_header2, "Two different images are the same!"


def test_section_cmd_header_info() -> None:
    """Test presence of all keywords in __str__() method of section header command.

    This test verifies that the string representation of CmdSectionHeader contains
    all required keywords (UID and Type) in its output format.
    """
    section_header = CmdSectionHeader(length=100)
    output = str(section_header)
    required_strings = ["UID", "Type"]
    for required_string in required_strings:
        assert required_string in output, f"String {required_string} is not in output"


def test_section_cmd_header_offset() -> None:
    """Test CmdSectionHeader.parse() error handling with insufficient data.

    This test verifies that parsing a section header command fails appropriately
    when the provided data buffer is too small (truncated to 50 bytes instead
    of the full exported data length).

    :raises SPSDKError: Expected exception when parsing truncated data.
    """
    section_header = CmdSectionHeader(length=100)
    data = section_header.export()
    with pytest.raises(SPSDKError):
        CmdSectionHeader.parse(data=data[50:])


def test_parse_command_function() -> None:
    """Test the parse_command function with various SB3.1 command types.

    This test validates that the parse_command function correctly identifies and parses
    different binary command formats into their corresponding command objects including
    CmdErase, CmdLoad, CmdExecute, CmdCall, CmdProgFuses, CmdProgIfr, CmdLoadCmac,
    CmdCopy, CmdLoadHashLocking, CmdLoadKeyBlob, CmdConfigureMemory, CmdFillMemory,
    and CmdFwVersionCheck.
    """
    # CmdErase(address=100, length=0, memory_id=0)
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdErase)

    # CmdLoad(address=100, length=0, memory_id=0)
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdLoad)

    # CmdExecute(address=100)
    data = b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00"
    parse = parse_command(data)
    assert isinstance(parse, CmdExecute)

    # CmdCall(address=100)
    data = b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00"
    parse = parse_command(data)
    assert isinstance(parse, CmdCall)

    # CmdProgFuses(address=100, data=[0, 1, 2, 3])
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x05\x00\x00\x00\x05\x00\x00\x00"
        b"\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00"
        b"\x00\x00\x04\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdProgFuses)

    # CmdProgIfr(address=100, data=(b"\x00" * 100))
    data = b"U\xaa\xaaUd\x00\x00\x00d\x00\x00\x00\x06\x00\x00\x00"
    parse = parse_command(data)
    assert isinstance(parse, CmdProgIfr)

    # CmdLoadCmac(address=100, length=0, memory_id=0)
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdLoadCmac)

    # CmdCopy(address=100, length=0, destination_address=0, memory_id_from=0, memory_id_to=0)
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdCopy)

    # CmdLoadHashLocking(address=100, length=0, memory_id=0)
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdLoadHashLocking)

    # CmdLoadKeyBlob(offset=100, key_wrap_id=CmdLoadKeyBlob.NXP_CUST_KEK_EXT_SK, data=10 * b"x")
    data = (
        b"U\xaa\xaaUd\x00\x11\x00\n\x00\x00\x00\n\x00\x00\x00xxxxxxxxxx" b"\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdLoadKeyBlob)

    # CmdConfigureMemory(address=100, memory_id=0)
    data = b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00"
    parse = parse_command(data)
    assert isinstance(parse, CmdConfigureMemory)

    # CmdFillMemory(address=100, memory_id=0)
    data = (
        b"U\xaa\xaaUd\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    parse = parse_command(data)
    assert isinstance(parse, CmdFillMemory)

    # CmdFwVersionCheck(value=100, counter_id=CmdFwVersionCheck.SECURE)
    data = b"U\xaa\xaaUd\x00\x00\x00\x02\x00\x00\x00\r\x00\x00\x00"
    parse = parse_command(data)
    assert isinstance(parse, CmdFwVersionCheck)


def test_invalid_parse_command_function() -> None:
    """Test invalid parse command function with malformed data.

    This test verifies that the parse_command function properly raises SPSDKError
    when provided with invalid or malformed command data, including both corrupted
    header data and zero-filled data of correct size.

    :raises SPSDKError: When parse_command receives invalid command data.
    """
    invalid_data = b"U\xaa\xaaUd\x00\x00\x00\t\x00\x00\x00\x00\x00\x00\x00"
    with pytest.raises(SPSDKError):
        parse_command(invalid_data)
    invalid_data = bytes(CmdSectionHeader.SIZE)
    with pytest.raises(SPSDKError):
        parse_command(invalid_data)


def test_invalid_tag_cmd_load_base() -> None:
    """Test that CmdLoadBase.parse raises SPSDKError for invalid tag data.

    This test verifies that the CmdLoadBase.parse method properly validates
    the command tag and raises an SPSDKError when provided with invalid
    tag data (all zeros in this case).

    :raises SPSDKError: Expected exception when parsing invalid tag data.
    """
    with pytest.raises(SPSDKError):
        CmdLoadBase.parse(data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")


def test_invalid_tag_cmd_prog_fuse() -> None:
    """Test that CmdProgFuses.parse raises SPSDKError for invalid tag data.

    Verifies that parsing command data with an invalid tag (all zeros) properly
    raises an SPSDKError exception, ensuring robust error handling for malformed
    fuse programming commands.

    :raises SPSDKError: When parsing data with invalid tag format.
    """
    with pytest.raises(SPSDKError):
        CmdProgFuses.parse(data=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")


def test_invalid_base_cmd() -> None:
    """Test invalid BaseCmd address and length values.

    Verifies that BaseCmd properly validates address and length parameters,
    raising SPSDKError when values exceed the maximum allowed range.

    :raises SPSDKError: When address or length values are invalid (exceed maximum range).
    """
    cmd = BaseCmd(address=0x00, length=1)
    with pytest.raises(SPSDKError, match="Invalid address"):
        cmd.address = 0xFFFFFFFFA
    with pytest.raises(SPSDKError, match="Invalid length"):
        cmd.length = 0xFFFFFFFFA


@pytest.mark.parametrize(
    "config,value,raise_error",
    [
        ({"address": 0, "value": "0x0FFFFFFE"}, b"\xfe\xff\xff\x0f", False),
        (
            {"address": 0, "values": "0x00000004,0x00020000,0xFFFFFFFF,0xFFFFFFFE"},
            b"\x04\x00\x00\x00\x00\x00\x02\x00\xff\xff\xff\xff\xfe\xff\xff\xff",
            False,
        ),
        (
            {"address": 0, "data": "option"},
            None,
            True,
        ),
    ],
)
def test_load_program_ifr_cmd(config: dict, value: Optional[bytes], raise_error: bool) -> None:
    """Test loading program IFR command from configuration.

    This test verifies that the CmdProgIfr.load_from_config method correctly
    handles various configuration inputs, either successfully creating a command
    or raising appropriate errors based on the configuration validity.

    :param config: Configuration dictionary for creating the program IFR command.
    :param value: Expected data value in the created command, None if error expected.
    :param raise_error: Flag indicating whether an SPSDKError should be raised.
    :raises SPSDKError: When raise_error is True and invalid configuration is provided.
    """
    if raise_error:
        with pytest.raises(SPSDKError):
            CmdProgIfr.load_from_config(Config(config))
    else:
        cmd = CmdProgIfr.load_from_config(Config(config))
        assert cmd[0].data == value


def test_cmd_write_ifr() -> None:
    """Test CmdWriteIfr command functionality.

    Validates that CmdWriteIfr command properly handles address, data, ifr_type,
    and info values. Tests export functionality with proper alignment and
    parsing capability to ensure round-trip consistency.
    """
    cmd = CmdWriteIfr(address=100, data=bytes([0] * 100), ifr_type=CmdWriteIfr.WriteIfrType.CFPA)
    assert cmd.address == 100
    assert cmd.data == bytes([0] * 100)
    assert cmd.ifr_type == CmdWriteIfr.WriteIfrType.CFPA
    assert str(cmd)

    data = cmd.export()
    assert len(data) % 16 == 0  # Check alignment
    assert len(data) == 16 + 16 + 112  # BaseCmd.SIZE + padding + data (aligned to 16)

    cmd_parsed = CmdWriteIfr.parse(data=data)
    assert cmd == cmd_parsed
    assert cmd.data == cmd_parsed.data
    assert cmd.ifr_type == cmd_parsed.ifr_type


def test_cmd_write_ifr_cfpa_and_cmpa() -> None:
    """Test WriteIFR command with CFPA_AND_CMPA type.

    This test verifies that the CmdWriteIfr command correctly handles the CFPA_AND_CMPA
    IFR type by creating a command instance, validating its properties, testing
    serialization/deserialization, and ensuring the parsed command matches the original.
    """
    cmd = CmdWriteIfr(
        address=100, data=bytes([0] * 100), ifr_type=CmdWriteIfr.WriteIfrType.CFPA_AND_CMPA
    )
    assert cmd.address == 100
    assert cmd.data == bytes([0] * 100)
    assert cmd.ifr_type == CmdWriteIfr.WriteIfrType.CFPA_AND_CMPA
    assert str(cmd)

    data = cmd.export()
    cmd_parsed = CmdWriteIfr.parse(data=data)
    assert cmd == cmd_parsed
    assert cmd.ifr_type == cmd_parsed.ifr_type == CmdWriteIfr.WriteIfrType.CFPA_AND_CMPA


def test_parse_invalid_cmd_write_ifr_cmd_tag() -> None:
    """Test CmdWriteIfr command parsing with invalid command tag.

    This test verifies that parsing a CmdWriteIfr command with an incorrect
    command tag raises the expected SPSDKError exception. It creates a valid
    CmdWriteIfr command, corrupts its tag, exports it, and attempts to parse
    the corrupted data.

    :raises SPSDKError: When parsing command data with invalid tag.
    """
    cmd = CmdWriteIfr(address=100, data=bytes([0] * 100), ifr_type=CmdWriteIfr.WriteIfrType.CFPA)
    cmd.CMD_TAG = EnumCmdTag.CALL
    data = cmd.export()
    with pytest.raises(SPSDKError):
        CmdWriteIfr.parse(data=data)


def test_cmd_write_ifr_load_from_config() -> None:
    """Test loading CmdWriteIfr from configuration.

    Validates that CmdWriteIfr commands can be properly loaded from configuration
    objects with different parameter formats including direct values and value lists.
    Tests both CFPA and CFPA_AND_CMPA IFR types to ensure correct address assignment,
    type setting, and data conversion from hexadecimal strings to bytes.
    """
    # Test with direct value
    config = Config({"type": "CFPA", "value": "0x12345678"})
    cmd = CmdWriteIfr.load_from_config(config)[0]
    assert cmd.address == 0x0
    assert cmd.ifr_type == CmdWriteIfr.WriteIfrType.CFPA
    assert cmd.data == b"\x78\x56\x34\x12"

    # Test with values list
    config = Config({"type": "CFPA_AND_CMPA", "values": "0x11111111,0x22222222,0x33333333"})
    cmd = CmdWriteIfr.load_from_config(config)[0]
    assert cmd.address == 0x0
    assert cmd.ifr_type == CmdWriteIfr.WriteIfrType.CFPA_AND_CMPA
    assert cmd.data == b"\x11\x11\x11\x11\x22\x22\x22\x22\x33\x33\x33\x33"


def test_cmd_write_ifr_get_config_context(tmpdir: str) -> None:
    """Test getting configuration context from CmdWriteIfr command.

    Verifies that CmdWriteIfr.get_config_context() method properly generates
    configuration context with correct address, type, and data file creation.
    The test creates a CmdWriteIfr instance with test data and validates that
    the configuration context contains expected values and the data file is
    created with correct content.

    :param tmpdir: Temporary directory path for test data files.
    """
    # Create a temporary directory for data files
    data_path = str(tmpdir)

    # Create a command
    test_data = bytes(range(16))
    cmd = CmdWriteIfr(address=0x3000, data=test_data, ifr_type=CmdWriteIfr.WriteIfrType.CFPA)

    # Get configuration context
    config = cmd.get_config_context(data_path=data_path)

    # Verify configuration
    assert config.get_int("address") == 0x3000
    assert config.get_str("type") == "CFPA"

    # Verify file was created and contains correct data
    file_path = os.path.join(data_path, config.get_str("file"))
    assert os.path.exists(file_path)
    with open(file_path, "rb") as f:
        file_data = f.read()
    assert file_data == test_data


def test_parse_command_write_ifr() -> None:
    """Test parse_command function with WriteIFR command.

    This test verifies that the parse_command function correctly parses binary data
    into a CmdWriteIfr command object. It creates a WriteIFR command with specific
    parameters, exports it to binary format, parses it back, and validates that
    all attributes are preserved correctly.

    :raises AssertionError: If the parsed command doesn't match expected values.
    """
    # Create binary data for a WriteIFR command
    cmd = CmdWriteIfr(
        address=0x4000, data=bytes([0xAA] * 16), ifr_type=CmdWriteIfr.WriteIfrType.CFPA
    )
    data = cmd.export()

    # Parse the command
    parsed_cmd = parse_command(data)

    # Verify the parsed command
    assert isinstance(parsed_cmd, CmdWriteIfr)
    assert parsed_cmd.address == 0x4000
    assert parsed_cmd.data == bytes([0xAA] * 16)
    assert parsed_cmd.ifr_type == CmdWriteIfr.WriteIfrType.CFPA


def test_cmd_write_ifr_invalid_config() -> None:
    """Test CmdWriteIfr command loading with invalid configuration parameters.

    Validates that CmdWriteIfr.load_from_config properly handles and rejects
    various invalid configuration scenarios including missing required fields,
    invalid field values, and incomplete data specifications.

    :raises KeyError: When required configuration fields are missing or invalid.
    :raises SPSDKError: When configuration lacks necessary data sources.
    """
    # Missing type
    config = Config({"value": "0x12345678"})
    with pytest.raises(KeyError):
        CmdWriteIfr.load_from_config(config)

    # Invalid type
    config = Config({"type": "INVALID_TYPE", "value": "0x12345678"})
    with pytest.raises(KeyError):
        CmdWriteIfr.load_from_config(config)

    # Missing data source
    config = Config({"type": "CFPA"})
    with pytest.raises(SPSDKError):
        CmdWriteIfr.load_from_config(config)


def test_cmd_check_lc() -> None:
    """Test export and parsing of CmdCheckLifecycle command.

    Verifies that CmdCheckLifecycle command can be properly created, exported to binary format,
    and parsed back from binary data while maintaining all properties and equality.

    :raises AssertionError: If any of the command properties don't match expected values or
        if parsed command doesn't equal original command.
    """
    cmd = CmdCheckLifecycle(lifecycle=CmdCheckLifecycle.Lifecycle.DEVELOP2)
    assert cmd.address == 0
    assert cmd.length == 0
    assert cmd.lifecycle == CmdCheckLifecycle.Lifecycle.DEVELOP2
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16

    cmd_parsed = CmdCheckLifecycle.parse(data=data)
    assert cmd == cmd_parsed
    assert cmd.lifecycle == cmd_parsed.lifecycle


def test_cmd_check_lc_load_from_config() -> None:
    """Test loading CmdCheckLifecycle from configuration.

    Verifies that CmdCheckLifecycle command can be properly loaded from configuration
    with valid lifecycle values and raises appropriate exceptions for invalid values.

    :raises KeyError: When an unknown lifecycle value is provided in configuration.
    """
    # Test with direct value
    config = Config({"lifecycle": CmdCheckLifecycle.Lifecycle.NXP_PROVISIONED.label})
    cmd = CmdCheckLifecycle.load_from_config(config)[0]
    assert cmd.lifecycle == CmdCheckLifecycle.Lifecycle.NXP_PROVISIONED
    config = Config({"lifecycle": "UNKNOWN"})
    with pytest.raises(KeyError):
        CmdCheckLifecycle.load_from_config(config)


def test_cmd_check_lc_get_config_context(tmpdir: str) -> None:
    """Test getting configuration context from CmdCheckLifecycle.

    This test verifies that the CmdCheckLifecycle command can properly generate
    a configuration context and that the lifecycle value is correctly set in
    the returned configuration.

    :param tmpdir: Temporary directory path for test files.
    """
    # Create a temporary directory for data files
    cmd = CmdCheckLifecycle(lifecycle=CmdCheckLifecycle.Lifecycle.IN_FIELD_RETURN)
    # Get configuration context
    config = cmd.get_config_context(data_path="")
    # Verify configuration
    assert config.get_str("lifecycle") == CmdCheckLifecycle.Lifecycle.IN_FIELD_RETURN.label
