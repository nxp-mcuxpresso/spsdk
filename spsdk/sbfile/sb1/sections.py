#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB1 boot sections implementation.

This module provides functionality for handling boot sections in SB1 (Secure Binary version 1) files,
including section parsing, validation, and management within the SPSDK framework.
"""

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
    """Boot Section for SB file version 1.x.

    This class represents a boot section within a Secure Binary (SB) file format version 1.x,
    managing section metadata through its header and containing a collection of boot commands.
    The section can be configured as bootable and includes flags for ROM processing control.
    """

    def __init__(self, section_id: int, flags: SecureBootFlagsV1 = SecureBootFlagsV1.NONE):
        """Initialize BootSectionV1.

        :param section_id: Unique section ID, 32-bit integer value.
        :param flags: Boot section flags, see SecureBootFlagsV1 enumeration.
        """
        self._header = BootSectionHeaderV1(section_id, flags)
        self._commands: list[CmdBaseClass] = []

    @property
    def section_id(self) -> int:
        """Get unique ID of the section.

        Returns the 32-bit unique identifier of the section from the header.

        :return: Section unique identifier as 32-bit integer.
        """
        return self._header.section_id

    @property
    def flags(self) -> SecureBootFlagsV1:
        """Get section flags.

        :return: Section flags containing security and operational settings.
        """
        return self._header.flags

    @property
    def bootable(self) -> bool:
        """Return whether section is bootable.

        :return: True if section is bootable, False otherwise.
        """
        return self._header.bootable

    @property
    def rom_last_tag(self) -> bool:
        """Get ROM_LAST_TAG flag.

        The last section header in an image always has its ROM_LAST_TAG flag set to help the ROM know at what point
        to stop searching.

        :return: True if this is the last section, False otherwise.
        """
        return self._header.rom_last_tag

    @rom_last_tag.setter
    def rom_last_tag(self, value: bool) -> None:
        """Set ROM last tag flag.

        :param value: ROM_LAST_TAG flag indicating if this is the last tag in ROM.
        """
        self._header.rom_last_tag = value

    @property
    def cmd_size(self) -> int:
        """Calculate the total size of all commands in binary representation.

        :return: Total size in bytes of all commands when serialized to binary format.
        """
        return sum(cmd.raw_size for cmd in self._commands)

    @property
    def size(self) -> int:
        """Return size of the binary representation of the section in bytes.

        :return: Size in bytes including header and command data.
        """
        result = self._header.raw_size + self.cmd_size
        return result

    def __repr__(self) -> str:
        """Return string representation of the BootSection-V1 object.

        :return: String containing section type and ID information.
        """
        return f"BootSection-V1, ID: {self._header.section_id}"

    def __str__(self) -> str:
        """Return string representation of the boot section.

        The string includes section header information (ID, number of blocks) and
        all commands contained within the section in a human-readable format.

        :return: Formatted string representation of the boot section.
        """
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
        """Return sequence of all commands in the section.

        :return: Sequence of all commands contained in this section.
        """
        return self._commands

    def append(self, cmd: CmdBaseClass) -> None:
        """Append command to the section.

        Adds a new command to the internal commands list. The command must be one of the
        supported SB1 command types.

        :param cmd: Command instance to be added to the section
        :raises AssertionError: If the command type is not supported
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
        """Update the internal settings of the section.

        This method recalculates and updates the number of blocks in the header
        based on the current command size.

        :raises SPSDKError: If block size calculation fails.
        """
        self._header.num_blocks = SecBootBlckSize.to_num_blocks(self.cmd_size)

    def export(self) -> bytes:
        """Export section to binary representation.

        The method updates the section header and serializes all commands into a binary format
        suitable for storage or transmission.

        :return: Binary data representing the complete section including header and commands.
        """
        self.update()
        data = self._header.export()
        for cmd in self._commands:
            data += cmd.export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse boot section from binary data format.

        Deserializes binary data into a boot section instance by parsing the header
        and extracting all commands within the section blocks.

        :param data: Binary data to be parsed into boot section.
        :return: Parsed boot section instance with header and commands.
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
