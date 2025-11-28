#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SBx secure boot file format support.

This module provides the SBx interface for secure boot file operations,
exposing commands and constants from the SB31 implementation for backward
compatibility and unified access.
"""

from spsdk.sbfile.sb31.commands import (
    CmdErase,
    CmdExecute,
    CmdLoad,
    CmdProgFuses,
    CmdReset,
    CmdSectionHeader,
    parse_command,
)
from spsdk.sbfile.sb31.constants import EnumCmdTag

__all__ = [
    # commands3
    "CmdErase",
    "CmdLoad",
    "CmdExecute",
    "CmdProgFuses",
    "CmdReset",
    "CmdSectionHeader",
    # constants
    "EnumCmdTag",
    # functions
    "parse_command",
]
