#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SBX commands API functionality.

This module contains unit tests for validating the behavior and functionality
of SBX (Secure Binary) commands used in SPSDK secure provisioning operations.
The tests ensure proper command creation, validation, and execution within
the SPSDK SBX command framework.
"""


from spsdk.sbfile.sb31.commands import CmdReset


def test_cmd_reset() -> None:
    """Test the CmdReset command functionality.

    Validates the CmdReset command by testing its default properties,
    string representation, data export functionality, and round-trip
    parsing to ensure the command can be properly serialized and
    deserialized.

    :raises AssertionError: If any of the command properties or operations don't match expected values.
    """
    cmd = CmdReset()
    assert cmd.address == 0
    assert cmd.length == 0
    assert str(cmd)

    data = cmd.export()
    assert len(data) == 16

    cmd_parsed = CmdReset.parse(data=data)
    assert cmd == cmd_parsed
