#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB Initialize command implementation for secure boot."""

from struct import pack, unpack_from
from typing import Iterator, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdTag, EngineEnum
from spsdk.image.hab.hab_header import CmdHeader


class CmdInitialize(CmdBase):
    """Initialize specified engine features when exiting ROM.

    +-------------+--------------+--------------+
    |     tag     |      len     |     eng      |
    +-------------+--------------+--------------+
    |                   [val]                   |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+
    """

    CMD_TAG = CmdTag.INIT

    def __init__(
        self, engine: EngineEnum = EngineEnum.ANY, data: Optional[list[int]] = None
    ) -> None:
        """Initialize the initialize command."""
        if engine not in EngineEnum:
            raise SPSDKError("Incorrect value of engine")
        super().__init__(engine.tag)
        self._data = data if data else []

    @property
    def engine(self) -> EngineEnum:
        """Engine."""
        return EngineEnum.from_tag(self._header.param)

    @engine.setter
    def engine(self, value: EngineEnum) -> None:
        if value not in EngineEnum:
            raise SPSDKError("Incorrect value of engine")
        self._header.param = value.tag

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} <{self.engine.label}, {len(self._data)}>"

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        return self._data.__iter__()

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Initialize Command (Engine: {self.engine.description})\n"
        cnt = 0
        for val in self._data:
            msg += f" {cnt:02d}) Value: 0x{val:08X}\n"
            cnt += 1
        return msg

    def append(self, value: int) -> None:
        """Appending of Initialize command.

        :raises SPSDKError: If value out of range
        """
        assert isinstance(value, int), "value must be INT type"
        if value < 0 or value >= 0xFFFFFFFF:
            raise SPSDKError("Value out of range")
        self._data.append(value)
        self._header.length += 4

    def pop(self, index: int) -> int:
        """Pop of Initialize command.

        :return: value from the index
        :raises SPSDKError: If incorrect length of data
        """
        if index < 0 or index >= len(self._data):
            raise SPSDKError("Incorrect length of data")
        val = self._data.pop(index)
        self._header.length -= 4
        return val

    def clear(self) -> None:
        """Clear of Initialize command."""
        self._data.clear()
        self._header.length = self._header.size

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        for val in self._data:
            raw_data += pack(">L", val)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        :raises SPSDKError: If incorrect length of data
        """
        header = CmdHeader.parse(data, CmdTag.INIT.tag)
        obj = cls(EngineEnum.from_tag(header.param))
        index = header.size
        while index < header.length:
            if index >= len(data):
                raise SPSDKError("Incorrect length of data")
            val = unpack_from(">L", data, index)
            obj.append(val[0])
            index += 4
        return obj
