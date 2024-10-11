#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Boot Selection for SB file."""

from typing import Sequence

from typing_extensions import Self

from spsdk.sbfile.misc import SecBootBlckSize
from spsdk.sbfile.sb1.commands import parse_v1_command
from spsdk.sbfile.sb1.headers import BootSectionHeaderV1, SecureBootFlagsV1
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
)
from spsdk.utils.abstract import BaseClass


class BootSectionV1(BaseClass):
    """Boot Section for SB file 1.x."""

    def __init__(self, section_id: int, flags: SecureBootFlagsV1 = SecureBootFlagsV1.NONE):
        """Initialize BootSectionV1.

        :param section_id: unique section ID, 32-bit int
        :param flags: see SecureBootFlagsV1
        """
        self._header = BootSectionHeaderV1(section_id, flags)
        self._commands: list[CmdBaseClass] = []

    @property
    def section_id(self) -> int:
        """Return unique ID of the section, 32 number."""
        return self._header.section_id

    @property
    def flags(self) -> SecureBootFlagsV1:
        """Return section flags."""
        return self._header.flags

    @property
    def bootable(self) -> bool:
        """Return whether section is bootable."""
        return self._header.bootable

    @property
    def rom_last_tag(self) -> bool:
        """ReturnROM_LAST_TAG flag.

        The last section header in an image always has its ROM_LAST_TAG flag set to help the ROM know at what point
        to stop searching.
        """
        return self._header.rom_last_tag

    @rom_last_tag.setter
    def rom_last_tag(self, value: bool) -> None:
        """Setter.

        :param value: ROM_LAST_TAG flag
        """
        self._header.rom_last_tag = value

    @property
    def cmd_size(self) -> int:
        """Return size of the binary representation of the commands."""
        return sum(cmd.raw_size for cmd in self._commands)

    @property
    def size(self) -> int:
        """Return size of the binary representation of the section in bytes."""
        result = self._header.raw_size + self.cmd_size
        return result

    def __repr__(self) -> str:
        return f"BootSection-V1, ID: {self._header.section_id}"

    def __str__(self) -> str:
        """Return string representation."""
        result = "[BootSection-V1]\n"
        result += f"ID: {self._header.section_id}\n"
        result += f"NumBlocks: {self._header.num_blocks}\n"
        result += str(self._header) + "\n"
        result += "[BootSection-commands]\n"
        for cmd in self._commands:
            result += str(cmd)
        return result

    @property
    def commands(self) -> Sequence[CmdBaseClass]:
        """Return sequence of all commands in the section."""
        return self._commands

    def append(self, cmd: CmdBaseClass) -> None:
        """Append command.

        :param cmd: to be added
        """
        assert isinstance(
            cmd,
            (
                CmdNop,
                CmdErase,
                CmdLoad,
                CmdFill,
                CmdJump,
                CmdCall,
                CmdReset,
                CmdMemEnable,
                CmdProg,
            ),
        )
        self._commands.append(cmd)

    def update(self) -> None:
        """Update settings."""
        self._header.num_blocks = SecBootBlckSize.to_num_blocks(self.cmd_size)

    def export(self) -> bytes:
        """Return binary representation of the class (serialization)."""
        self.update()
        data = self._header.export()
        for cmd in self._commands:
            data += cmd.export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Deserialization from binary format.

        :param data: to be parsed
        :return: the parsed instance
        """
        header = BootSectionHeaderV1.parse(data)
        result = cls(0)
        result._header = header
        # commands
        cmd_base = header.raw_size
        cmd_ofs = 0
        end_ofs = result._header.num_blocks * SecBootBlckSize.BLOCK_SIZE
        while cmd_ofs < end_ofs:
            cmd = parse_v1_command(data[cmd_base + cmd_ofs :])
            result.append(cmd)
            cmd_ofs += cmd.raw_size
        return result
