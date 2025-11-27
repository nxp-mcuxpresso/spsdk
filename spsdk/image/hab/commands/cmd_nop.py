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
    """HAB No-Operation command implementation.

    This command represents a no-operation instruction in the HAB (High Assurance Boot)
    command sequence. It has no functional effect and can be used as a placeholder
    or for alignment purposes in command sequences.
    The command structure consists of a standard HAB command header with tag, length,
    and an undefined parameter field::

    +-------------+--------------+--------------+
    |     tag     |      len     |     undef    |
    +-------------+--------------+--------------+

    :cvar CMD_TAG: Command tag identifier for NOP operations.
    """

    CMD_TAG = CmdTag.NOP

    def __init__(self, param: int = 0):
        """Initialize the nop command.

        :param param: Parameter value for the nop command, defaults to 0.
        """
        super().__init__(param)

    def __repr__(self) -> str:
        """Return string representation of the HAB NOP command object.

        :return: Class name as string representation.
        """
        return self.__class__.__name__

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into NOP command object.

        Deserializes binary representation of a NOP (No Operation) command into a command object
        by extracting and validating the command header.

        :param data: Binary data to be parsed into NOP command.
        :return: Parsed NOP command object.
        """
        header = CmdHeader.parse(data, CmdTag.NOP.tag)
        if header.length != header.size:
            pass
        return cls(header.param)
