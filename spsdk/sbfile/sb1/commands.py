#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB1 command parsing and management utilities.

This module provides functionality for parsing and handling SB1 (Secure Binary version 1)
commands within the SPSDK framework. It includes command parsing capabilities and
integrates with the SB2 command infrastructure for unified command processing.
"""

from typing import Mapping, Type

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2.commands import (
    CmdBaseClass,
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
    EnumCmdTag,
)

# mapping of V1.x command to the implementation class
_CMDV1_TO_CLASS: Mapping[EnumCmdTag, Type[CmdBaseClass]] = {
    EnumCmdTag.NOP: CmdNop,
    EnumCmdTag.TAG: CmdTag,
    EnumCmdTag.LOAD: CmdLoad,
    EnumCmdTag.FILL: CmdFill,
    EnumCmdTag.JUMP: CmdJump,
    EnumCmdTag.CALL: CmdCall,
    # RESERVED == 06
    EnumCmdTag.ERASE: CmdErase,
    EnumCmdTag.RESET: CmdReset,
    EnumCmdTag.MEM_ENABLE: CmdMemEnable,
    EnumCmdTag.PROG: CmdProg,
}


def parse_v1_command(data: bytes) -> CmdBaseClass:
    """Parse SB V1.x command from binary format.

    This method extracts the command tag from the binary data and creates
    the appropriate command object based on the tag type.

    :param data: Input binary data containing the SB V1.x command
    :raises SPSDKError: Raised when there is unsupported command tag
    :return: Parsed command object instance
    """
    header_tag = EnumCmdTag.from_tag(data[1])
    if header_tag not in _CMDV1_TO_CLASS:
        raise SPSDKError(f"Unsupported command: {header_tag.label}")
    return _CMDV1_TO_CLASS[header_tag].parse(data)
