#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SB31 module of sbfile."""

from spsdk.sbfile.sb31.commands import (
    CmdCall,
    CmdConfigureMemory,
    CmdCopy,
    CmdErase,
    CmdExecute,
    CmdFillMemory,
    CmdLoad,
    CmdLoadCmac,
    CmdLoadHashLocking,
    CmdLoadKeyBlob,
    CmdProgFuses,
    CmdProgIfr,
    CmdSectionHeader,
    parse_command,
)
from spsdk.sbfile.sb31.constants import EnumCmdTag

__all__ = [
    # commands3
    "CmdErase",
    "CmdLoad",
    "CmdExecute",
    "CmdCall",
    "CmdProgFuses",
    "CmdProgIfr",
    "CmdLoadCmac",
    "CmdLoadHashLocking",
    "CmdCopy",
    "CmdFillMemory",
    "CmdLoadKeyBlob",
    "CmdConfigureMemory",
    "CmdSectionHeader",
    # constants
    "EnumCmdTag",
    # methods
    "parse_command",
]
