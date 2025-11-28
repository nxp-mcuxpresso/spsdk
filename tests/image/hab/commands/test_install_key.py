#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB Install Key command tests.

This module contains unit tests for the HAB (High Assurance Boot) Install Key
command functionality, verifying command creation, parsing, serialization,
and validation operations.
"""

from spsdk.image.hab.commands.cmd_install_key import InstallKeyFlagsEnum, SecCmdInstallKey
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.constants import CertFormatEnum, EnumAlgorithm


def test_install_key_cmd_base() -> None:
    """Test SecCmdInstallKey command initialization and basic functionality.

    Verifies that a SecCmdInstallKey instance is created with correct default values
    and that setting flags properly updates the internal header parameter.

    :raises AssertionError: If any of the default values or flag setting behavior is incorrect.
    """
    cmd = SecCmdInstallKey()
    assert cmd.flags == InstallKeyFlagsEnum.CLR
    assert cmd.certificate_format == CertFormatEnum.SRK
    assert cmd.hash_algorithm == EnumAlgorithm.ANY
    assert cmd.source_index == 0
    assert cmd.target_index == 0
    assert cmd.cmd_data_location == 0
    assert cmd.size == 12

    cmd.flags = InstallKeyFlagsEnum.MID
    assert cmd._header.param == InstallKeyFlagsEnum.MID


def test_install_key_cmd_repr() -> None:
    """Test the string representation of SecCmdInstallKey command.

    Verifies that the repr() output of SecCmdInstallKey contains all required
    string identifiers to ensure proper debugging and logging capabilities.

    :raises AssertionError: When required string is not found in representation output.
    """
    cmd = SecCmdInstallKey()
    representation = repr(cmd)
    req_strings = ["CmdInstallKey"]
    for req_string in req_strings:
        assert (
            req_string in representation
        ), f"string {req_string} is not in the output: {representation}"


def test_install_key_cmd_equality() -> None:
    """Test equality comparison for SecCmdInstallKey command objects.

    Verifies that SecCmdInstallKey objects properly implement equality comparison
    by testing against different object types and configurations. Tests include
    comparison with non-matching object types, self-comparison, and comparison
    with objects having different configuration flags.
    """
    cmd = SecCmdInstallKey()
    nop = CmdNop()
    cmd_other = SecCmdInstallKey(flags=InstallKeyFlagsEnum.CID)

    assert cmd != nop
    assert cmd == cmd
    assert cmd != cmd_other


def test_install_key_cmd_export_parse() -> None:
    """Test SecCmdInstallKey export and parse functionality.

    Verifies that the SecCmdInstallKey command can be properly exported to binary data
    and then parsed back to recreate the original command object. Tests data length
    consistency and round-trip serialization integrity.
    """
    cmd = SecCmdInstallKey()
    data = cmd.export()
    assert len(data) == 12
    assert len(data) == cmd.size
    assert cmd == SecCmdInstallKey.parse(data)


def test_install_key_cmd_info() -> None:
    """Test Install Key command string representation.

    Verifies that the string representation of SecCmdInstallKey command contains
    all required information fields including command name, flag, certificate format,
    algorithm, source key index, target key index, and location.

    :raises AssertionError: If any required string is missing from command output.
    """
    cmd = SecCmdInstallKey()
    output = str(cmd)
    req_strings = [
        'Command "Install Key',
        "Flag",
        "CertFormat",
        "Algorithm",
        "SrcKeyIdx",
        "TgtKeyIdx",
        "Location",
    ]

    for req_string in req_strings:
        assert req_string in output, f"string {req_string} is not in the output: {output}"
