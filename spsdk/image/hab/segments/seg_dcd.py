#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Device Configuration Data (DCD) segment module for HAB.

This module implements the Device Configuration Data (DCD) segment used in HAB-enabled bootable images.
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
    """Device configuration data (DCD) segment.

    IC configuration data, usually is used to configure DDR/SDRAM memory. Typically this is optional
    """

    # list of supported DCD commands
    _COMMANDS: tuple[CmdTag, ...] = (
        CmdTag.WRT_DAT,
        CmdTag.CHK_DAT,
        CmdTag.NOP,
        CmdTag.UNLK,
    )

    def __init__(self, param: int = 0x41, enabled: bool = False) -> None:
        """Initialize DCD segment."""
        super().__init__()
        self.enabled = enabled
        self._header = Header(SegmentTag.DCD.tag, param)
        self._header.length = self._header.size
        self._commands: list[CmdBase] = []

    @property
    def header(self) -> Header:
        """Header of Device configuration data (DCD) segment."""
        return self._header

    @property
    def commands(self) -> list[CmdBase]:
        """Commands of Device configuration data (DCD) segment."""
        return self._commands

    @property
    def size(self) -> int:
        """Size of Device configuration data (DCD) segment."""
        return self._header.length if self.enabled else 0

    @property
    def space(self) -> int:
        """Add space."""
        return self.size + self.padding if self.enabled else 0

    def __repr__(self) -> str:
        return f"DCD <Commands: {len(self._commands)}>"

    def __len__(self) -> int:
        return len(self._commands)

    def __getitem__(self, key: int) -> CmdBase:
        return self._commands[key]

    def __setitem__(self, key: int, value: CmdBase) -> None:
        if value.tag not in self._COMMANDS:
            raise SPSDKError("Invalid command")
        self._commands[key] = value

    def __iter__(self) -> Iterator:
        return self._commands.__iter__()

    def __str__(self) -> str:
        """String representation of the SegDCD."""
        msg = ""
        for cmd in self._commands:
            msg += str(cmd) + "\n"
        return msg

    def append(self, cmd: CmdBase) -> None:
        """Appending of Device configuration data (DCD) segment."""
        if not (isinstance(cmd, CmdBase) and (cmd.tag in self._COMMANDS)):
            raise SPSDKError("Invalid command")
        self._commands.append(cmd)
        self._header.length += cmd.size

    def pop(self, index: int) -> CmdBase:
        """Popping of Device configuration data (DCD) segment."""
        if index < 0 or index >= len(self._commands):
            raise SPSDKError("Can not pop item from dcd segment")
        cmd = self._commands.pop(index)
        self._header.length -= cmd.size
        return cmd

    def clear(self) -> None:
        """Clear of Device configuration data (DCD) segment."""
        self._commands.clear()
        self._header.length = self._header.size

    def export_txt(self, txt_data: Optional[str] = None) -> str:
        """Export txt of Device configuration data (DCD) segment."""
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

        :return: bytes
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

        :param text: The string with DCD commands
        :return: SegDCD object
        """
        return SegDcdBuilder().build(text)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse segment from bytes array.

        :param data: The bytes array of DCD segment
        :raises SPSDKCorruptedException: Exception caused by corrupted data
        :return: SegDCD object
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

    This class represents the DCD segment in the context of HAB images.
    DCD is used to configure hardware peripherals (typically memory like DDR/SDRAM)
    before the main application starts execution.
    """

    SEGMENT_IDENTIFIER = HabSegmentEnum.DCD

    def __init__(self, dcd: SegDCD):
        """Initialize the segment."""
        super().__init__()
        self.dcd = dcd

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the DCD HAB segment from HAB configuration.

        :param config: Hab configuration object
        :return: Instance of DCD HAB segment.
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

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of DCD HAB segment.
        """
        ivt = HabSegmentIvt.parse(data)
        if ivt.dcd_address:
            offset = ivt.dcd_address - ivt.ivt_address
            segment = cls(SegDCD.parse(data[offset:]))
            segment.offset = offset
            return segment
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    def export(self) -> bytes:
        """Export segment as bytes.

        :return: bytes
        """
        return self.dcd.export()

    @property
    def size(self) -> int:
        """Size of the binary data."""
        return self.dcd.size


class SegDcdBuilder:
    """Builder to create SegDCD from text input."""

    def __init__(self) -> None:
        """Initialize SegDcdBuilder."""
        self.line_cnt = 0  # current line number to be displayed in the error message
        self.cmd_write: Optional[CmdWriteData] = (
            None  # this is cache to merge several write commands of same type
        )

    def _parse_cmd(self, dcd_obj: SegDCD, cmd: list[str]) -> None:
        """Parse one command.

        :param dcd_obj: result of the builder
        :param cmd: command with arguments
        :raises SPSDKError: command is corrupted
        :raises SPSDKError: When command is unsupported
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

        :param text: input text to import
        :return: SegDCD object
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
