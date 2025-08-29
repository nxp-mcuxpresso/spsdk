#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of sbc."""

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.sbfile.sbc.images import SecureBinaryC, SecureBinaryCCommands, SecureBinaryCHeader
from spsdk.utils.family import FamilyRevision


def test_secure_binary_c_creation():
    header = SecureBinaryCHeader(
        firmware_version=1, description="Test SBC file", timestamp=12345678
    )
    sbc = SecureBinaryC(
        family=FamilyRevision("mcxa366"),
        firmware_version=1,
        description="Test SBC file",
        timestamp=12345678,
    )
    header.validate()
    sbc.validate()
    assert isinstance(sbc, SecureBinaryC)


def test_secure_binary_c_description():
    header = SecureBinaryCHeader(firmware_version=1, description="abc", timestamp=12345678)
    header.validate()
    assert header.description == b"abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def test_secure_binary_c_max_timestamp():
    header = SecureBinaryCHeader(
        firmware_version=1, description="Test max timestamp", timestamp=0xFFFFFFFF
    )
    header.validate()
    assert header.timestamp == 0xFFFFFFFF


# Test basic creation and validation
def test_secure_binary_c_creation():
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
def test_secure_binary_c_export():
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


def test_secure_binary_c_firmware_version_boundaries():
    """Test boundary values for firmware version."""
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


def test_secure_binary_c_equality():
    """Test equality comparison of SBC objects."""
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
