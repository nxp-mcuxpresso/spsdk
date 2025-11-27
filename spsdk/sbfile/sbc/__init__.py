#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Secure Binary Container (SBc) module.

This module provides the SBc implementation for SPSDK sbfile package,
offering secure boot container functionality with command parsing and
execution capabilities.
"""

from spsdk.sbfile.sb31.commands import (
    CmdErase,
    CmdExecute,
    CmdLoad,
    CmdLoadKeyBlob,
    CmdSectionHeader,
    parse_command,
)
from spsdk.sbfile.sb31.constants import EnumCmdTag

__all__ = [
    # commands3
    "CmdErase",
    "CmdLoad",
    "CmdExecute",
    "CmdLoadKeyBlob",
    "CmdSectionHeader",
    # constants
    "EnumCmdTag",
    # functions
    "parse_command",
]
