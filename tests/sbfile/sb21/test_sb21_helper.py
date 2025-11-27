#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test suite for SB21Helper class functionality.

This module contains comprehensive unit tests for the SB21Helper class,
which provides helper functions for creating and managing SB2.1 (Secure Binary 2.1)
file commands in SPSDK. Tests verify proper command generation, error handling,
and parameter validation for SB2.1 file creation workflows.
"""

from typing import Any, Dict, Optional, Union
from unittest.mock import patch

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.commands import (
    CmdErase,
    CmdFill,
    CmdJump,
    CmdKeyStoreBackup,
    CmdKeyStoreRestore,
    CmdLoad,
    CmdMemEnable,
    CmdVersionCheck,
    VersionCheckType,
)
from spsdk.sbfile.sb2.sb_21_helper import SB21Helper
from spsdk.utils.misc import value_to_int


@pytest.mark.parametrize(
    "address, argument, spreg",
    [
        (0x1000, 0x2000, 0x800),
        (4096, 8192, 2048),
        ("0x1000", "0x2000", "2048"),
        ("4096", "8192", "2048"),
        ("4096", "8192", None),
    ],
)
def test_jump_with_various_inputs(
    address: Union[int, str], argument: Union[int, str], spreg: Optional[Union[int, str]]
) -> None:
    """Test that _jump method correctly handles various input formats.

    Validates that the SB21Helper._jump method properly processes different
    input types (int, str) for address, argument, and optional spreg parameters,
    and returns a correctly configured CmdJump object.

    :param address: Jump target address as integer or string representation
    :param argument: Jump argument value as integer or string representation
    :param spreg: Optional stack pointer register value as integer or string representation
    :raises AssertionError: If the _jump method doesn't produce expected CmdJump object or values
    """
    helper = SB21Helper()
    cmd_args: Dict[str, Any] = {"address": address, "argument": argument}
    if spreg:
        cmd_args["spreg"] = spreg
    result = helper._jump(cmd_args)
    assert isinstance(result, CmdJump)
    assert result.address == value_to_int(address)
    assert result.argument == value_to_int(argument)
    if spreg:
        assert result.spreg == value_to_int(spreg)
    else:
        assert result.spreg is None


@pytest.mark.parametrize(
    "address, load_opt, expected_mem_id",
    [
        (0x70000000, None, 0),
        ("0x70000000", None, 0),
        (0x70000000, 8, 8),
        (0x70000000, "8", 8),
        (0x70000000, "0x8", 8),
    ],
)
def test_load_with_file_parametrized(
    address: Union[int, str], load_opt: Optional[Union[int, str]], expected_mem_id: int
) -> None:
    """Test _load method with file parameter and various input formats.

    This test verifies that the SB21Helper._load method correctly processes
    command arguments containing a file parameter with different address and
    load option formats, ensuring proper CmdLoad object creation.

    :param address: Memory address for load operation, accepts int or string format
    :param load_opt: Optional load options parameter, accepts int, string or None
    :param expected_mem_id: Expected memory ID value for verification
    """
    helper = SB21Helper()

    # Create cmd_args with file
    cmd_args: Dict[str, Any] = {"address": address, "file": "myBinFile"}

    # Add load_opt if provided
    if load_opt is not None:
        cmd_args["load_opt"] = load_opt

    # Mock dependencies
    with patch(
        "spsdk.sbfile.sb2.sb_21_helper.load_binary", return_value=b"test_data"
    ) as mock_load_binary:
        result = helper._load(cmd_args)

    # Verify the result
    assert isinstance(result, CmdLoad)
    assert result.address == value_to_int(address)
    assert result.mem_id == expected_mem_id
    assert result.data == b"test_data"
    mock_load_binary.assert_called_once_with("myBinFile", None)


@pytest.mark.parametrize(
    "cmd_args, expected_error_msg",
    [
        ({"address": 0x1000}, "Unsupported LOAD command args"),
        ({"address": 0x1000, "pattern": 0x55}, "Unsupported LOAD command args"),
        ({"address": 0x1000, "values": "1,4294967296"}, "Invalid values for load command"),
        ({"address": 0x1000, "values": "1,-1"}, "Invalid values for load command"),
    ],
)
def test_load_error_cases_parametrized(cmd_args: Dict[str, Any], expected_error_msg: str) -> None:
    """Test _load method error cases with various input formats.

    This test function validates that the SB21Helper._load method properly raises
    SPSDKError exceptions with expected error messages when provided with invalid
    command arguments.

    :param cmd_args: Dictionary containing command arguments to test with invalid or problematic values
    :param expected_error_msg: Expected error message that should be contained in the raised exception
    :raises SPSDKError: When the helper._load method encounters invalid input (expected behavior)
    :raises AssertionError: When the actual error message doesn't contain the expected error message
    """
    helper = SB21Helper()

    # Test that the correct error is raised
    with pytest.raises(SPSDKError) as excinfo:
        helper._load(cmd_args)

    assert expected_error_msg in str(excinfo.value)


@pytest.mark.parametrize(
    "address, pattern, expected_address, expected_pattern",
    [
        (0x2000, 0x102, 0x2000, "01020102"),
        (4096, 258, 4096, "01020102"),
        ("0x2000", "0x102", 0x2000, "01020102"),
        ("4096", "258", 4096, "01020102"),
        (0x2000, "0x102", 0x2000, "01020102"),
        ("0x2000", 0x102, 0x2000, "01020102"),
        ("0b10000000000", "0b000100000010", 0x400, "01020102"),
    ],
)
def test_fill_memory_with_various_inputs(
    address: Union[int, str], pattern: Union[int, str], expected_address: int, expected_pattern: str
) -> None:
    """Test _fill_memory method with various input formats for address and pattern.

    Validates that the SB21Helper._fill_memory method correctly processes different
    input formats for address and pattern parameters and returns a properly
    configured CmdFill object with expected values.

    :param address: Memory address in integer or string format to be tested
    :param pattern: Fill pattern in integer or string format to be tested
    :param expected_address: Expected integer address value after processing
    :param expected_pattern: Expected hexadecimal pattern string after processing
    """
    helper = SB21Helper()
    cmd_args: Dict[str, Any] = {"address": address, "pattern": pattern}
    result = helper._fill_memory(cmd_args)
    assert isinstance(result, CmdFill)
    assert result.address == expected_address
    assert result.pattern == bytes.fromhex(expected_pattern)
    assert result.zero_filling is False  # Default value


@pytest.mark.parametrize(
    "address, length, flags, mem_opt, expected_address, expected_length, expected_flags, expected_mem_id",
    [
        (0x8001000, 0x1000, 0, None, 0x8001000, 0x1000, 0, 0),
        (0x8001000, 0x1000, 1, 8, 0x8001000, 0x1000, 2049, 8),
        ("0x8001000", "0x1000", "0", None, 0x8001000, 0x1000, 0, 0),
        ("0x8001000", "0x1000", "1", "8", 0x8001000, 0x1000, 2049, 8),
        ("134279168", "4096", "0", None, 0x800F000, 0x1000, 0, 0),
        ("134279168", "4096", "1", "8", 0x800F000, 0x1000, 2049, 8),
        (0x8001000, "0x1000", 0, "8", 0x8001000, 0x1000, 2048, 8),
        ("0x8001000", 0x1000, "0", 8, 0x8001000, 0x1000, 2048, 8),
        ("0b1000000000000001000000000000", "0b1000000000000", "0b0", None, 0x8001000, 0x1000, 0, 0),
        (0, 0, 0, None, 0, 0, 0, 0),
        (0, 0, 0, "mmccard", 0, 0, 8464, 289),
    ],
)
def test_erase_cmd_handler_with_various_inputs(
    address: Union[int, str],
    length: Union[int, str],
    flags: Union[int, str],
    mem_opt: Optional[Union[int, str]],
    expected_address: int,
    expected_length: int,
    expected_flags: int,
    expected_mem_id: int,
) -> None:
    """Test _erase_cmd_handler method with various input formats.

    Validates that the SB21Helper._erase_cmd_handler method correctly processes
    different input parameter types (int, str) and optional parameters to create
    a CmdErase object with expected values.

    :param address: Memory address for erase operation (int or string format).
    :param length: Length of memory to erase (int or string format).
    :param flags: Erase operation flags (int or string format).
    :param mem_opt: Optional memory identifier (int or string format).
    :param expected_address: Expected address value in the resulting CmdErase object.
    :param expected_length: Expected length value in the resulting CmdErase object.
    :param expected_flags: Expected flags value in the resulting CmdErase object.
    :param expected_mem_id: Expected memory ID value in the resulting CmdErase object.
    """
    helper = SB21Helper()
    cmd_args: Dict[str, Any] = {
        "address": address,
    }
    if length is not None:
        cmd_args["length"] = length
    if flags is not None:
        cmd_args["flags"] = flags
    if mem_opt is not None:
        cmd_args["mem_opt"] = mem_opt
    result = helper._erase_cmd_handler(cmd_args)
    assert isinstance(result, CmdErase)
    assert result.address == expected_address
    assert result.length == expected_length
    assert result.flags == expected_flags
    assert result.mem_id == expected_mem_id


@pytest.mark.parametrize(
    "address, size, mem_opt, expected_address, expected_size, expected_mem_id",
    [
        (0x20001000, 4, None, 0x20001000, 4, 0),
        (0x20001000, 8, 1, 0x20001000, 8, 1),
        ("0x20001000", "4", None, 0x20001000, 4, 0),
        ("0x20001000", "8", "1", 0x20001000, 8, 1),
        ("536875008", "4", None, 0x20001000, 4, 0),
        ("536875008", "8", "1", 0x20001000, 8, 1),
        (0x20001000, "4", None, 0x20001000, 4, 0),
        ("0x20001000", 8, "1", 0x20001000, 8, 1),
        ("0x20001000", "0x4", None, 0x20001000, 4, 0),
        ("0x20001000", "0x8", "0x1", 0x20001000, 8, 1),
        (0x20001000, 4, "qspi", 0x20001000, 4, 1),
    ],
)
def test_enable_with_various_inputs(
    address: Union[int, str],
    size: Union[int, str],
    mem_opt: Optional[Union[int, str]],
    expected_address: int,
    expected_size: int,
    expected_mem_id: int,
) -> None:
    """Test _enable method with various input formats.

    Validates that the SB21Helper._enable method correctly processes different
    input parameter formats (int/str) and produces the expected CmdMemEnable
    command with proper address, size, and memory ID values.

    :param address: Memory address as integer or string format
    :param size: Memory size as integer or string format
    :param mem_opt: Memory option as integer, string format, or None
    :param expected_address: Expected resulting address value
    :param expected_size: Expected resulting size value
    :param expected_mem_id: Expected resulting memory ID value
    """
    helper = SB21Helper()
    cmd_args: Dict[str, Any] = {
        "address": address,
    }
    if size is not None:
        cmd_args["size"] = size
    if mem_opt is not None:
        cmd_args["mem_opt"] = mem_opt

    result = helper._enable(cmd_args)
    assert isinstance(result, CmdMemEnable)
    assert result.address == expected_address
    assert result.size == expected_size
    assert result.mem_id == expected_mem_id


@pytest.mark.parametrize(
    "mem_opt, address, expected_mem_id, expected_address",
    [
        (9, 0x8000800, 9, 0x8000800),
        ("0x9", "0x8000800", 9, 0x8000800),
        ("9", "134219776", 9, 0x8000800),
        ("0b1001", "0b1000000000000000100000000000", 9, 0x8000800),
    ],
)
def test_keystore_to_nv_with_various_inputs(
    mem_opt: Union[int, str], address: Union[int, str], expected_mem_id: int, expected_address: int
) -> None:
    """Test _keystore_to_nv method with various input formats.

    Validates that the SB21Helper._keystore_to_nv method correctly processes
    different input formats for memory options and addresses, ensuring proper
    conversion to CmdKeyStoreRestore command with expected values.

    :param mem_opt: Memory option identifier, can be integer or string format.
    :param address: Target address for keystore restoration, can be integer or string format.
    :param expected_mem_id: Expected memory identifier after processing.
    :param expected_address: Expected address value after processing.
    """
    helper = SB21Helper()
    cmd_args: Dict[str, Any] = {"mem_opt": mem_opt, "address": address}
    result = helper._keystore_to_nv(cmd_args)
    assert isinstance(result, CmdKeyStoreRestore)
    assert result.address == expected_address


@pytest.mark.parametrize(
    "address, mem_opt, expected_address",
    [
        (0x8000800, 9, 0x8000800),
        ("0x8000800", "9", 0x8000800),
        ("0x8000800", "0x9", 0x8000800),
        ("134219776", "9", 0x8000800),
    ],
)
def test_keystore_from_nv_with_various_inputs(
    address: Union[int, str], mem_opt: Union[int, str], expected_address: int
) -> None:
    """Test _keystore_from_nv method with various input formats.

    Validates that the SB21Helper._keystore_from_nv method correctly processes
    different input formats for address and memory options, ensuring proper
    conversion to CmdKeyStoreBackup object with expected address value.

    :param address: Memory address in various formats (int or string).
    :param mem_opt: Memory option specification in various formats (int or string).
    :param expected_address: Expected final address value after processing.
    """
    helper = SB21Helper()
    cmd_args: Dict[str, Any] = {"address": address, "mem_opt": mem_opt}
    result = helper._keystore_from_nv(cmd_args)
    assert isinstance(result, CmdKeyStoreBackup)
    assert result.address == expected_address


@pytest.mark.parametrize(
    "ver_type, fw_version, expected_ver_type, expected_fw_version",
    [
        # Integer inputs
        (0, 2, VersionCheckType.SECURE_VERSION, 2),
        (1, 3, VersionCheckType.NON_SECURE_VERSION, 3),
        ("0", "2", VersionCheckType.SECURE_VERSION, 2),
        ("1", "3", VersionCheckType.NON_SECURE_VERSION, 3),
        ("0x0", "0x2", VersionCheckType.SECURE_VERSION, 2),
        ("0x1", "0x3", VersionCheckType.NON_SECURE_VERSION, 3),
    ],
)
def test_version_check_with_various_inputs(
    ver_type: Union[int, str],
    fw_version: Union[int, str],
    expected_ver_type: VersionCheckType,
    expected_fw_version: int,
) -> None:
    """Test _version_check method with various input formats.

    Validates that the SB21Helper._version_check method correctly processes
    different input types and formats for version checking parameters,
    ensuring proper conversion to expected types and values.

    :param ver_type: Version check type as integer or string format
    :param fw_version: Firmware version as integer or string format
    :param expected_ver_type: Expected VersionCheckType enum value after processing
    :param expected_fw_version: Expected firmware version integer after processing
    """
    helper = SB21Helper()

    # Create cmd_args with the test inputs
    cmd_args: Dict[str, Any] = {"ver_type": ver_type, "fw_version": fw_version}

    # Call the method
    result = helper._version_check(cmd_args)

    # Verify the result
    assert isinstance(result, CmdVersionCheck)
    assert result.type == expected_ver_type
    assert result.version == expected_fw_version
