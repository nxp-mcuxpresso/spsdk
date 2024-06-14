#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for SBFile."""

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

    :param data: Input data as bytes
    :return: parsed command object
    :raises SPSDKError: Raised when there is unsupported command
    """
    header_tag = EnumCmdTag.from_tag(data[1])
    if header_tag not in _CMDV1_TO_CLASS:
        raise SPSDKError(f"Unsupported command: {header_tag.label}")
    return _CMDV1_TO_CLASS[header_tag].parse(data)
