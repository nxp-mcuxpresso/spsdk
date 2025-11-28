#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Device Configuration Data (DCD) segment module for HAB.

This module implements the Device Configuration Data (DCD) segment used in HAB-enabled bootable images.
The DCD segment contains initialization commands that configure the target device before the main
application code execution.
"""

import logging
from typing import Iterator, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKCorruptedException, SPSDKError, SPSDKSyntaxError
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.hab.commands.cmd_check_data import CheckDataOpsEnum, CmdCheckData
from spsdk.image.hab.commands.cmd_nop import CmdNop
from spsdk.image.hab.commands.cmd_unlock import CmdUnlockAny
from spsdk.image.hab.commands.cmd_write_data import CmdWriteData, WriteDataOpsEnum
from spsdk.image.hab.commands.commands import CmdBase, parse_command
from spsdk.image.hab.constants import CmdTag, EngineEnum
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.image.hab.segments.seg_ivt import HabSegmentIvt
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum, PaddingSegment
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary

logger = logging.getLogger(__name__)


class SegDCD(PaddingSegment):
    """Device Configuration Data (DCD) segment for HAB images.

    This segment contains IC configuration data used to configure DDR/SDRAM memory
    and other hardware components during boot. The DCD segment is typically optional
    and supports various commands for writing data, checking data, and unlocking registers.

    :cvar _COMMANDS: Tuple of supported DCD command tags including write data, check data, NOP, and unlock commands.
    """

    # list of supported DCD commands
    _COMMANDS: tuple[CmdTag, ...] = (
        CmdTag.WRT_DAT,
        CmdTag.CHK_DAT,
        CmdTag.NOP,
        CmdTag.UNLK,
    )

    def __init__(self, param: int = 0x41, enabled: bool = False) -> None:
        """Initialize DCD segment.

        Creates a new Device Configuration Data (DCD) segment with specified parameters
        and initializes the internal command list and header structure.

        :param param: Parameter value for the DCD header, defaults to 0x41
        :param enabled: Whether the DCD segment is enabled, defaults to False
        """
        super().__init__()
        self.enabled = enabled
        self._header = Header(SegmentTag.DCD.tag, param)
        self._header.length = self._header.size
        self._commands: list[CmdBase] = []

    @property
    def header(self) -> Header:
        """Get header of Device Configuration Data (DCD) segment.

        :return: Header object containing DCD segment header information.
        """
        return self._header

    @property
    def commands(self) -> list[CmdBase]:
        """Get commands of Device Configuration Data (DCD) segment.

        :return: List of DCD commands contained in this segment.
        """
        return self._commands

    @property
    def size(self) -> int:
        """Size of Device configuration data (DCD) segment.

        Returns the length from the header if the segment is enabled, otherwise returns 0.

        :return: Size of the DCD segment in bytes, or 0 if disabled.
        """
        return self._header.length if self.enabled else 0

    @property
    def space(self) -> int:
        """Get the space required by this segment.

        Calculates the total space needed for the segment, including padding,
        but only if the segment is enabled.

        :return: Total space in bytes, or 0 if segment is disabled.
        """
        return self.size + self.padding if self.enabled else 0

    def __repr__(self) -> str:
        """Return string representation of DCD segment.

        Provides a concise string representation showing the number of commands
        contained in the DCD segment.

        :return: String representation in format "DCD <Commands: {count}>".
        """
        return f"DCD <Commands: {len(self._commands)}>"

    def __len__(self) -> int:
        """Get the number of DCD commands.

        :return: Number of commands in the DCD segment.
        """
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBase:
        """Get command at specified index.

        :param key: Index of the command to retrieve.
        :return: Command object at the specified index.
        """
        return self._commands[key]

    def __setitem__(self, key: int, value: CmdBase) -> None:
        """Set command at specified index in the DCD segment.

        This method allows updating or replacing a command at a specific position
        in the DCD commands list.

        :param key: Index position where to set the command.
        :param value: Command object to be set at the specified index.
        :raises SPSDKError: If the command tag is not supported by DCD segment.
        """
        if value.tag not in self._COMMANDS:
            raise SPSDKError("Invalid command")
        self._commands[key] = value

    def __iter__(self) -> Iterator:
        """Get iterator over DCD commands.

        Provides iteration capability over the internal commands collection,
        allowing for sequential access to all DCD commands in the segment.

        :return: Iterator over the DCD commands.
        """
        return self._commands.__iter__()

    def __str__(self) -> str:
        """String representation of the SegDCD.

        Creates a formatted string containing all DCD commands in the segment,
        with each command on a separate line.

        :return: Multi-line string representation of all commands in the segment.
        """
        msg = ""
        for cmd in self._commands:
            msg += str(cmd) + "\n"
        return msg

    def append(self, cmd: CmdBase) -> None:
        """Append command to Device Configuration Data (DCD) segment.

        Adds a new command to the DCD segment and updates the header length
        to reflect the added command size.

        :param cmd: Command to be appended to the DCD segment
        :raises SPSDKError: Invalid command type or unsupported command tag
        """
        if not (isinstance(cmd, CmdBase) and (cmd.tag in self._COMMANDS)):
            raise SPSDKError("Invalid command")
        self._commands.append(cmd)
        self._header.length += cmd.size

    def pop(self, index: int) -> CmdBase:
        """Remove command from Device Configuration Data (DCD) segment at specified index.

        The method removes a command from the internal commands list and updates
        the header length accordingly.

        :param index: Index of the command to remove from the segment.
        :raises SPSDKError: Invalid index or unable to remove item from DCD segment.
        :return: The removed command object.
        """
        if index < 0 or index >= len(self._commands):
            raise SPSDKError("Can not pop item from dcd segment")
        cmd = self._commands.pop(index)
        self._header.length -= cmd.size
        return cmd

    def clear(self) -> None:
        """Clear the Device Configuration Data (DCD) segment.

        Removes all commands from the DCD segment and resets the header length
        to the base header size.
        """
        self._commands.clear()
        self._header.length = self._header.size

    def export_txt(self, txt_data: Optional[str] = None) -> str:
        """Export Device Configuration Data (DCD) segment to text format.

        Converts the DCD segment commands into a human-readable text representation. The method
        processes different command types (WriteData, CheckData, UnlockAny) and formats them
        according to their specific syntax requirements.

        :param txt_data: Optional existing text data to append to, defaults to empty string.
        :return: Formatted text representation of the DCD segment commands.
        """
        write_ops = ("WriteValue", "WriteClearBits", "ClearBitMask", "SetBitMask")
        check_ops = ("CheckAllClear", "CheckAllSet", "CheckAnyClear", "CheckAnySet")
        if txt_data is None:
            txt_data = ""

        for cmd in self._commands:
            if isinstance(cmd, CmdWriteData):
                for address, value in cmd:
                    txt_data += (
                        f"{write_ops[cmd.ops.tag]} {cmd.num_bytes} 0x{address:08X} 0x{value:08X}\n"
                    )
            elif isinstance(cmd, CmdCheckData):
                txt_data += (
                    f"{check_ops[cmd.ops.tag]} {cmd.num_bytes} 0x{cmd.address:08X} 0x{cmd.mask:08X}"
                )
                txt_data += f" {cmd.count}\n" if cmd.count else "\n"

            elif isinstance(cmd, CmdUnlockAny):
                txt_data += f"Unlock {cmd.engine.label}"
                cnt = 1
                for value in cmd:
                    if cnt > 6:
                        txt_data += " \\\n"
                        cnt = 0
                    txt_data += f" 0x{value:08X}"
                    cnt += 1

                txt_data += "\n"

            else:
                txt_data += "Nop\n"

            # Split with new line every group of commands
            txt_data += "\n"

        return txt_data

    def export(self) -> bytes:
        """Export segment as bytes array.

        Exports the DCD segment data including header, commands, and padding when enabled.
        If the segment is disabled, returns empty bytes.

        :return: Exported segment data as bytes array.
        """
        data = b""
        if self.enabled:
            data = self._header.export()
            for command in self._commands:
                data += command.export()
            # padding
            data += self._padding_export()

        return data

    @classmethod
    def parse_txt(cls, text: str) -> "SegDCD":
        """Parse segment from text file.

        This method creates a SegDCD object by parsing DCD (Device Configuration Data) commands
        from a text string representation.

        :param text: The string containing DCD commands to be parsed.
        :return: SegDCD object created from the parsed text commands.
        """
        return SegDcdBuilder().build(text)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse segment from bytes array.

        This method parses a DCD (Device Configuration Data) segment from a byte array,
        creating a SegDCD object with all contained commands.

        :param data: The bytes array containing the DCD segment data.
        :raises SPSDKCorruptedException: Exception caused by corrupted data or unknown commands.
        :return: SegDCD object with parsed header and commands.
        """
        header = Header.parse(data, SegmentTag.DCD.tag)
        index = header.size
        obj = cls(header.param, True)
        while index < header.length:
            try:
                cmd_obj = parse_command(data[index:])
            except ValueError as exc:
                raise SPSDKCorruptedException("Unknown command at position: " + hex(index)) from exc

            obj.append(cmd_obj)
            index += cmd_obj.size
        return obj


class HabSegmentDcd(HabSegmentBase):
    """HAB Device Configuration Data (DCD) segment.

    This class represents the DCD segment in HAB images, which is used to configure
    hardware peripherals (typically memory controllers like DDR/SDRAM) before the
    main application starts execution. The segment handles parsing, loading, and
    exporting of DCD data within the HAB container structure.

    :cvar SEGMENT_IDENTIFIER: HAB segment type identifier for DCD segments.
    """

    SEGMENT_IDENTIFIER = HabSegmentEnum.DCD

    def __init__(self, dcd: SegDCD):
        """Initialize the segment with DCD data.

        :param dcd: DCD segment containing device configuration data.
        """
        super().__init__()
        self.dcd = dcd

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the DCD HAB segment from HAB configuration.

        The method parses the DCD file path from configuration options and creates a DCD segment
        instance with proper offset calculation based on IVT addresses.

        :param config: HAB configuration object containing DCD file path and other options.
        :return: Instance of DCD HAB segment with configured offset.
        :raises SPSDKSegmentNotPresent: When DCDFilePath is not specified in configuration options.
        """
        options = config.get_config("options")
        if options.get("DCDFilePath"):
            segment = cls(SegDCD.parse(load_binary(options.get_input_file_name("DCDFilePath"))))
            ivt = HabSegmentIvt.load_from_config(config)
            segment.offset = ivt.dcd_address - ivt.ivt_address
            return segment
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse DCD segment block from image binary.

        Extracts the Device Configuration Data (DCD) segment from HAB container binary data
        by locating the DCD address from the Image Vector Table and parsing the segment data.

        :param data: Binary data of HAB container to be parsed.
        :param family: Target MCU family revision information.
        :return: Instance of DCD HAB segment with parsed data and offset.
        :raises SPSDKSegmentNotPresent: When DCD segment is not present in the container.
        """
        ivt = HabSegmentIvt.parse(data)
        if ivt.dcd_address:
            offset = ivt.dcd_address - ivt.ivt_address
            segment = cls(SegDCD.parse(data[offset:]))
            segment.offset = offset
            return segment
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    def export(self) -> bytes:
        """Export segment as bytes array.

        Converts the DCD (Device Configuration Data) segment into its binary representation
        that can be written to memory or included in bootable images.

        :return: Binary representation of the DCD segment.
        """
        return self.dcd.export()

    @property
    def size(self) -> int:
        """Get the size of the binary data.

        :return: Size of the DCD binary data in bytes.
        """
        return self.dcd.size


class SegDcdBuilder:
    """DCD (Device Configuration Data) segment builder for HAB images.

    This class provides functionality to build SegDCD objects from textual command
    input, parsing and converting text-based DCD commands into their binary
    representations for use in HAB (High Assurance Boot) images.
    """

    def __init__(self) -> None:
        """Initialize SegDcdBuilder.

        Sets up a new DCD (Device Configuration Data) segment builder with default values.
        Initializes line counter for error reporting and command write cache for merging
        consecutive write operations of the same type.
        """
        self.line_cnt = 0  # current line number to be displayed in the error message
        self.cmd_write: Optional[CmdWriteData] = (
            None  # this is cache to merge several write commands of same type
        )

    def _parse_cmd(self, dcd_obj: SegDCD, cmd: list[str]) -> None:
        """Parse one command from DCD script and add it to the DCD object.

        The method processes different types of DCD commands including write operations,
        check operations, NOP commands, and unlock commands. Write commands are batched
        together when possible for optimization.

        :param dcd_obj: DCD segment object to append the parsed command to
        :param cmd: List of command strings where first element is command name
        :raises SPSDKError: When command is corrupted or has insufficient arguments
        :raises SPSDKError: When command is unsupported or unknown
        :raises SPSDKSyntaxError: When check command has insufficient arguments
        """
        # ----------------------------
        # Parse command
        # ----------------------------
        cmd_tuple = _SEG_DCD_COMMANDS[cmd[0]]
        if cmd_tuple is None:
            if cmd[0] == "Nop":
                if self.cmd_write is not None:
                    dcd_obj.append(self.cmd_write)
                    self.cmd_write = None

                dcd_obj.append(CmdNop())

            elif cmd[0] == "Unlock":
                if self.cmd_write is not None:
                    dcd_obj.append(self.cmd_write)
                    self.cmd_write = None

                if cmd[1] not in EngineEnum:
                    raise SPSDKError(
                        f"Unlock CMD: wrong engine parameter at line {self.line_cnt - 1}"
                    )

                engine = EngineEnum.from_label(cmd[1])
                args = [int(value, 0) for value in cmd[2:]]
                dcd_obj.append(CmdUnlockAny(engine, *args))
            else:
                raise SPSDKError("Unknown command")

        elif cmd_tuple[0] == "write":
            if len(cmd) < 4:
                raise SPSDKError(f"Write CMD: not enough arguments at line {self.line_cnt - 1}")

            ops = cmd_tuple[1]
            assert isinstance(ops, WriteDataOpsEnum)
            numbytes = int(cmd[1])
            addr = int(cmd[2], 0)
            value = int(cmd[3], 0)

            if self.cmd_write is not None:
                if (self.cmd_write.ops != ops) or (self.cmd_write.num_bytes != numbytes):
                    dcd_obj.append(self.cmd_write)
                    self.cmd_write = None

            if self.cmd_write is None:
                self.cmd_write = CmdWriteData(numbytes, ops)

            self.cmd_write.append(addr, value)

        else:
            if len(cmd) < 4:
                raise SPSDKSyntaxError(
                    f"Check CMD: not enough arguments at line {self.line_cnt - 1}"
                )

            if self.cmd_write is not None:
                dcd_obj.append(self.cmd_write)
                self.cmd_write = None

            ops = cmd_tuple[1]
            assert isinstance(ops, CheckDataOpsEnum)
            numbytes = int(cmd[1])
            addr = int(cmd[2], 0)
            mask = int(cmd[3], 0)
            count = int(cmd[4], 0) if len(cmd) > 4 else None
            dcd_obj.append(CmdCheckData(numbytes, ops, addr, mask, count))

    def build(self, text: str) -> SegDCD:
        """Parse segment from text file and build SegDCD.

        The method processes DCD (Device Configuration Data) commands from text input,
        handling multi-line commands and building a complete SegDCD object with all
        parsed commands.

        :param text: Input text containing DCD commands to parse and import.
        :return: SegDCD object with parsed commands and enabled state.
        """
        dcd_obj = SegDCD(enabled=True)
        cmd_mline = False
        cmd: list[str] = []
        for line in text.split("\n"):
            line = line.rstrip("\0")
            line = line.lstrip()
            # increment line counter
            self.line_cnt += 1
            # ignore comments
            if not line or line.startswith("#"):
                continue
            # check if multi-line command
            if cmd_mline:
                cmd += line.split()
                cmd_mline = False
            else:
                cmd = line.split()
                if cmd[0] not in _SEG_DCD_COMMANDS:
                    logger.error(f"Unknown DCD command ignored: {cmd}")
                    continue
            #
            if cmd[-1] == "\\":
                cmd = cmd[:-1]
                cmd_mline = True
                continue

            self._parse_cmd(dcd_obj, cmd)

        if self.cmd_write is not None:
            dcd_obj.append(self.cmd_write)

        return dcd_obj


_SEG_DCD_COMMANDS = {
    "WriteValue": ("write", WriteDataOpsEnum.WRITE_VALUE),
    "WriteClearBits": ("write", WriteDataOpsEnum.WRITE_CLEAR_BITS),
    "ClearBitMask": ("write", WriteDataOpsEnum.CLEAR_BITMASK),
    "SetBitMask": ("write", WriteDataOpsEnum.SET_BITMASK),
    "CheckAllClear": ("check", CheckDataOpsEnum.ALL_CLEAR),
    "CheckAllSet": ("check", CheckDataOpsEnum.ALL_SET),
    "CheckAnyClear": ("check", CheckDataOpsEnum.ANY_CLEAR),
    "CheckAnySet": ("check", CheckDataOpsEnum.ANY_SET),
    "Unlock": None,
    "Nop": None,
}
