#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SB31 image API functionality.

This module contains comprehensive unit tests for the SecureBinary31 image API,
covering header validation, command management, error handling, and parsing
functionality in the SB31 secure boot format.
"""


import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31 import commands
from spsdk.sbfile.sb31.images import SecureBinary31Commands, SecureBinary31Header
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary
from spsdk.utils.spsdk_enum import SpsdkEnum

lpc_family = FamilyRevision("lpc55s3x")


def test_sb31_header_error() -> None:
    """Test SecureBinary31Header error handling scenarios.

    This test validates that SecureBinary31Header properly raises SPSDKError
    exceptions for various invalid input conditions including invalid magic
    bytes, version, block size, and hash algorithm types.

    :raises SPSDKError: When invalid header data is provided during parsing
        or when invalid hash algorithm types are used.
    """

    class TestEnumHashAlgorithm(SpsdkEnum):
        """Test enumeration for hash algorithms.

        This class extends SpsdkEnum to provide test-specific hash algorithm values
        for testing invalid hash algorithm scenarios in SecureBinary31Header.

        :cvar SHA256b: Test hash algorithm value for validation testing.
        """

        SHA256b = (0, "SHA256b", "SHA256b")

    # invalid MAGIC
    with pytest.raises(SPSDKError):
        SecureBinary31Header.parse(bytes(100))

    # invalid VERSION
    with pytest.raises(SPSDKError):
        SecureBinary31Header.parse(b"sbv3" + bytes(100))

    # invalid BLOCK_SIZE
    with pytest.raises(SPSDKError):
        SecureBinary31Header.parse(b"sbv3\x01\x00\x03\x00" + bytes(100))

    # invalid CURVE_NAME
    with pytest.raises(SPSDKError):
        SecureBinary31Header(firmware_version=1, hash_type=EnumHashAlgorithm.MD5)

    # invalid CURVE_NAME
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256)
    header.hash_type = TestEnumHashAlgorithm.SHA256b  # type: ignore[assignment]
    with pytest.raises(SPSDKError):
        assert header.block_size
    with pytest.raises(SPSDKError):
        assert header.cert_block_offset


def test_sb31_header_description() -> None:
    """Test SecureBinary31Header description field functionality.

    Verifies that the description field in SecureBinary31Header is properly handled
    including default empty description, normal description padding, and truncation
    of overly long descriptions to fit the 16-byte limit.
    """
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256)
    assert header.description == bytes(16)
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256, description="desc")
    assert header.description == b"desc" + bytes(12)
    header = SecureBinary31Header(1, EnumHashAlgorithm.SHA256, description="very long description")
    assert header.description == b"very long descri"
    assert str(header)


def test_sb31_commands_errors() -> None:
    """Test that SecureBinary31Commands.parse raises SPSDKError with invalid data.

    Verifies that parsing invalid byte data (100 zero bytes) through
    SecureBinary31Commands.parse method properly raises SPSDKError exception.

    :raises SPSDKError: Expected exception when parsing invalid data.
    """
    with pytest.raises(SPSDKError):
        SecureBinary31Commands.parse(bytes(100))


def test_sb31_commands_add() -> None:
    """Test adding commands to SecureBinary31Commands container.

    Verifies that commands can be successfully added to the SecureBinary31Commands
    object and that the command count and string representation are correct.
    The test creates a SecureBinary31Commands instance, adds a CALL command,
    and validates the container state.
    """
    sc = SecureBinary31Commands(family=lpc_family, hash_type=EnumHashAlgorithm.SHA256)
    sc.add_command(commands.CmdCall(0x100))
    assert len(sc.commands) == 1
    info = str(sc)
    assert "CALL: Address=" in info


def test_sb31_commands_insert() -> None:
    """Test insertion of commands into SecureBinary31Commands at specific positions.

    This test verifies that commands can be inserted at the beginning (index 0) and
    at the end (index -1) of the command list, and that the commands are properly
    stored and can be identified by their string representation.

    :raises AssertionError: If command insertion fails or commands are not in expected positions.
    """
    sc = SecureBinary31Commands(family=lpc_family, hash_type=EnumHashAlgorithm.SHA256)
    sc.insert_command(0, commands.CmdCall(0x100))
    sc.insert_command(-1, commands.CmdExecute(0x100))
    assert len(sc.commands) == 2
    assert "CALL:" in str(sc.commands[0])
    assert "EXECUTE:" in str(sc.commands[1])


def test_sb31_parse(data_dir: str) -> None:
    """Test SB3.1 file parsing functionality.

    This test verifies that a SecureBinary31Header can be correctly parsed from
    a binary SB3 file and validates the expected hash algorithm and image length.

    :param data_dir: Directory path containing test data files
    :raises AssertionError: If parsed header values don't match expected values
    """
    data = load_binary(f"{data_dir}/sb3_384_384.sb3")
    header = SecureBinary31Header.parse(data)
    assert header.hash_type == EnumHashAlgorithm.SHA384
    assert header.image_total_length == 0x2C8
