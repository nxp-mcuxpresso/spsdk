#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SBFile version 1 implementation.

This module provides complete functionality for creating, parsing, and manipulating
Secure Binary (SB) files version 1, including headers, sections, images, and related
utilities for NXP MCU secure boot process.
"""

from spsdk.sbfile.misc import BcdVersion3
from spsdk.sbfile.sb1.headers import SecureBootFlagsV1
from spsdk.sbfile.sb1.images import SecureBootV1
from spsdk.sbfile.sb1.sections import BootSectionV1
from spsdk.sbfile.sb2 import commands
from spsdk.sbfile.sb2.commands import (
    CmdCall,
    CmdErase,
    CmdFill,
    CmdJump,
    CmdLoad,
    CmdMemEnable,
    CmdNop,
    CmdProg,
    CmdReset,
    CmdTag,
)

__all__ = [
    # modules
    "commands",
    # main classes
    "SecureBootV1",
    "BootSectionV1",
    # commands
    "CmdFill",
    "CmdNop",
    "CmdTag",
    "CmdMemEnable",
    "CmdErase",
    "CmdReset",
    "CmdCall",
    "CmdLoad",
    "CmdJump",
    "CmdProg",
    # helper classes and enums
    "SecureBootFlagsV1",
    "BcdVersion3",
]
