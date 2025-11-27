#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB NOP command unit tests.

This module contains comprehensive unit tests for the HAB (High Assurance Boot)
NOP (No Operation) command functionality in SPSDK. Tests verify command creation,
serialization, parsing, equality comparison, and information retrieval.
"""

from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_set import CmdSet


def test_nop_cmd() -> None:
    """Test NOP command creation and basic properties.

    Verifies that a CmdNop object can be created with a parameter value,
    has the correct string representation, is not None, and has the expected
    size of 4 bytes.
    """
    cmd = CmdNop(param=0)
    assert "CmdNop" in repr(cmd)
    assert cmd is not None
    assert cmd.size == 4


def test_nop_cmd_eq() -> None:
    """Test that CmdNop and CmdSet commands are not equal.

    Verifies that the equality operator correctly identifies that a CmdNop
    instance is not equal to a CmdSet instance, ensuring proper command
    type differentiation.
    """
    cmd = CmdNop()
    cmd_set = CmdSet()
    assert cmd != cmd_set


def test_nop_cmd_info() -> None:
    """Test that CmdNop command info string contains expected text.

    Verifies that the string representation of a CmdNop instance
    contains the expected "No Operation" command identifier.
    """
    cmd = CmdNop()
    assert 'Command "No Operation' in str(cmd)


def test_nop_export_parse() -> None:
    """Test NOP command export and parse functionality.

    Verifies that a CmdNop command can be exported to binary data and then
    parsed back to create an equivalent command object. Also validates that
    the exported data has the expected length of 4 bytes.

    :raises AssertionError: If the exported data length is not 4 bytes or if the parsed command doesn't match the original.
    """
    cmd = CmdNop()
    data = cmd.export()
    assert len(data) == 4
    assert cmd == CmdNop.parse(data)
