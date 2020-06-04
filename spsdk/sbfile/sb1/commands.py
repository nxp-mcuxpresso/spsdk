#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands for SBFile."""

from typing import Mapping, Type

from ..commands import CmdBaseClass, EnumCmdTag
from ..commands import CmdNop, CmdTag, CmdLoad, CmdFill, CmdJump, CmdCall, CmdErase, CmdReset, CmdMemEnable, CmdProg

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


def parse_v1_command(data: bytes, offset: int = 0) -> CmdBaseClass:
    """Parse SB V1.x command from binary format.

    :param data: Input data as bytes
    :param offset: The offset of input data to start parsing
    :return: parsed command object
    :raise ValueError: raised when there is unsupported command
    """
    header_tag = EnumCmdTag.from_int(data[offset + 1])
    if header_tag not in _CMDV1_TO_CLASS:
        raise ValueError(f'Unsupported command: {EnumCmdTag.name(header_tag)}')
    return _CMDV1_TO_CLASS[header_tag].parse(data, offset)
