#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB NOP command implementation.

This module contains the implementation of the HAB No Operation command
which has no effect when executed but can be used for padding or placeholders
in HAB command sequences.
"""
from typing_extensions import Self

from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdTag
from spsdk.image.hab.hab_header import CmdHeader


class CmdNop(CmdBase):
    """This command has no effect.

    +-------------+--------------+--------------+
    |     tag     |      len     |     undef    |
    +-------------+--------------+--------------+
    """

    CMD_TAG = CmdTag.NOP

    def __init__(self, param: int = 0):
        """Initialize the nop command."""
        super().__init__(param)

    def __repr__(self) -> str:
        return self.__class__.__name__

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.NOP.tag)
        if header.length != header.size:
            pass
        return cls(header.param)
