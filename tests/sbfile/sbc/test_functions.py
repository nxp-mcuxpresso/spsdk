#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Secure Binary Container (SBC) functionality tests.

This module contains comprehensive test cases for SecureBinaryC class and related
SBC components, ensuring proper creation, configuration, and export functionality.
"""

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.sbfile.sbc.images import SecureBinaryC, SecureBinaryCCommands, SecureBinaryCHeader
from spsdk.utils.family import FamilyRevision


def test_secure_binary_c_description() -> None:
    """Test SecureBinaryCHeader description field handling.

    Validates that the SecureBinaryCHeader properly handles and pads the description
    field to the expected length with null bytes when initialized with a short string.

    :raises AssertionError: If description field is not properly padded to expected length.
    """
    header = SecureBinaryCHeader(firmware_version=1, description="abc", timestamp=12345678)
    header.validate()
    assert header.description == b"abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_secure_binary_c_max_timestamp() -> None:
    """Test secure binary C header with maximum timestamp value.

    Validates that a SecureBinaryCHeader can be created and validated
    with the maximum possible timestamp value (0xFFFFFFFF) without
    raising any exceptions.
    """
    header = SecureBinaryCHeader(
        firmware_version=1, description="Test max timestamp", timestamp=0xFFFFFFFF
    )
    header.validate()
    assert header.timestamp == 0xFFFFFFFF


# Test basic creation and validation
def test_secure_binary_c_creation() -> None:
    """Test creation of SecureBinaryC object with basic configuration.

    This test verifies that a SecureBinaryC object can be successfully created
    with a family revision, commands, firmware version, and description. It also
    validates the object and confirms it's an instance of SecureBinaryC.

    :raises AssertionError: If the created object is not an instance of SecureBinaryC.
    """
    family = FamilyRevision("mcxa366")
    commands = SecureBinaryCCommands(family=family, hash_type=EnumHashAlgorithm.SHA256)
    sbc = SecureBinaryC(
        family=family,
        firmware_version=1,
        commands=commands,
        description="Test SBC file",
    )
    sbc.validate()
    assert isinstance(sbc, SecureBinaryC)


# Test exporting functionality
def test_secure_binary_c_export() -> None:
    """Test secure binary C export functionality.

    Verifies that SecureBinaryC can be properly instantiated with MCXA366 family
    configuration and exports valid binary data with correct properties.

    :raises AssertionError: If exported binary is not bytes type or has zero length.
    """
    family = FamilyRevision("mcxa366")
    commands = SecureBinaryCCommands(family=family, hash_type=EnumHashAlgorithm.SHA256)
    sbc = SecureBinaryC(
        family=family,
        firmware_version=1,
        commands=commands,
        description="Test SBC file",
    )
    binary = sbc.export()
    assert isinstance(binary, bytes)
    assert len(binary) > 0


def test_secure_binary_c_firmware_version_boundaries() -> None:
    """Test boundary values for firmware version in SecureBinaryCHeader.

    Validates that SecureBinaryCHeader accepts and properly validates both minimum
    and maximum valid firmware version values (0 and 0xFFFFFFFF respectively).
    This test ensures the firmware version field handles 32-bit boundary conditions
    correctly without raising validation errors.
    """
    # Test minimum valid version
    min_version = SecureBinaryCHeader(
        firmware_version=0, description="Minimum version", timestamp=12345678  # Assuming 0 is valid
    )
    min_version.validate()

    # Test maximum valid version
    max_version = SecureBinaryCHeader(
        firmware_version=0xFFFFFFFF,  # Assuming 32-bit
        description="Maximum version",
        timestamp=12345678,
    )
    max_version.validate()


def test_secure_binary_c_equality() -> None:
    """Test equality comparison of SecureBinaryC objects.

    Verifies that two SecureBinaryC instances with identical parameters are considered equal,
    and that instances with different parameters are not equal. Tests the __eq__ method
    implementation for proper equality comparison logic.
    """
    family = FamilyRevision("mcxa366")
    commands = SecureBinaryCCommands(family=family, hash_type=EnumHashAlgorithm.SHA256)

    sbc1 = SecureBinaryC(
        family=family,
        firmware_version=1,
        description="Test equality",
        commands=commands,
    )

    sbc2 = SecureBinaryC(
        family=family,
        firmware_version=1,
        description="Test equality",
        commands=commands,
    )

    sbc3 = SecureBinaryC(
        family=family,
        firmware_version=2,  # Different version
        description="Test equality",
        commands=commands,
    )

    # Assuming __eq__ is implemented, otherwise this would test object identity
    assert sbc1 == sbc2
    assert sbc1 != sbc3
