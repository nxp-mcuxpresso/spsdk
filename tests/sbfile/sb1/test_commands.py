#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB1 commands parsing test module.

This module contains unit tests for parsing and validation of SB1 (Secure Binary version 1)
command structures in SPSDK. Tests cover both valid command parsing scenarios and
error handling for invalid command formats.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb1 import CmdNop
from spsdk.sbfile.sb1.commands import parse_v1_command


def test_parse_command() -> None:
    """Test parsing of a command by exporting and re-parsing it.

    This test verifies that a CmdNop command can be exported to binary format
    and then successfully parsed back to an equivalent command object.

    :raises AssertionError: If the parsed command does not match the original command.
    """
    cmd = CmdNop()
    parsed_cmd = parse_v1_command(cmd.export())
    assert parsed_cmd == cmd


def test_parse_invalid_command_tag() -> None:
    """Test parsing of invalid command tags in SB1 format.

    Verifies that parse_v1_command function properly raises SPSDKError
    when encountering invalid command tags or unsupported commands.

    :raises SPSDKError: When invalid command tag or unsupported command is provided.
    """
    # invalid tag
    with pytest.raises(SPSDKError):
        parse_v1_command(b"\xee" * 16)
    # unsupported command
    with pytest.raises(SPSDKError):
        parse_v1_command(b"\x0d" * 16)
