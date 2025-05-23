#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module implementing HAB Write Data command.

This module contains classes for creating, modifying, and serializing HAB Write Data commands,
which are used to write values to memory addresses during secure boot operations.
"""
from struct import pack, unpack_from
from typing import Iterable, Iterator, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdTag
from spsdk.image.hab.hab_header import CmdHeader
from spsdk.utils.spsdk_enum import SpsdkEnum


class WriteDataOpsEnum(SpsdkEnum):
    """Enum definition for 'flags' control flags in 'par' parameter of Write Data command."""

    WRITE_VALUE = (0, "WRITE_VALUE", "Write value")
    WRITE_CLEAR_BITS = (1, "WRITE_CLEAR_BITS", "Write clear bits")
    CLEAR_BITMASK = (2, "CLEAR_BITMASK", "Clear bitmask")
    SET_BITMASK = (3, "SET_BITMASK", "Set bitmask")


class CmdWriteData(CmdBase):
    """Write data command.

    +-------------+--------------+--------------+
    |     tag     |      len     |     par      |
    +-------------+--------------+--------------+
    |                  address                  |
    +-------------------------------------------+
    |                  val_msk                  |
    +-------------------------------------------+
    |                 [address]                 |
    +-------------------------------------------+
    |                 [val_msk]                 |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+
    |                 [address]                 |
    +-------------------------------------------+
    |                 [val_msk]                 |
    +-------------------------------------------+
    """

    CMD_TAG = CmdTag.WRT_DAT

    def __init__(
        self,
        numbytes: int = 4,
        ops: WriteDataOpsEnum = WriteDataOpsEnum.WRITE_VALUE,
        data: Optional[Iterable[tuple[int, int]]] = None,
    ) -> None:
        """Initialize Write Data command.

        :param numbytes: number of bytes. Must be value: 1, 2 or 4
        :param ops: type of write operation
        :param data: list of tuples: address and value
        :raises SPSDKError: When incorrect number of bytes
        :raises SPSDKError: When incorrect type of operation
        """
        if numbytes not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        if ops not in WriteDataOpsEnum:
            raise SPSDKError("Incorrect type of operation")
        super().__init__(((int(ops.tag) & 0x3) << 3) | (numbytes & 0x7))
        self._data: list[list[int]] = []
        if data is not None:
            assert isinstance(data, (list, tuple))
            for address, value in data:
                self.append(address, value)

    @property
    def num_bytes(self) -> int:
        """Number of bytes being written by the command."""
        return self._header.param & 0x7

    @num_bytes.setter
    def num_bytes(self, value: int) -> None:
        """Setter.

        :param value: number of bytes being written by the command
        :raises SPSDKError: When number of bytes is not 1, 2 nor 4
        """
        if value not in (1, 2, 4):
            raise SPSDKError("number of bytes is not 1, 2 nor 4")
        self._header.param &= ~0x7
        self._header.param |= value

    @property
    def ops(self) -> WriteDataOpsEnum:
        """Type of write operation."""
        return WriteDataOpsEnum.from_tag((self._header.param >> 3) & 0x3)

    @ops.setter
    def ops(self, value: WriteDataOpsEnum) -> None:
        if value not in WriteDataOpsEnum:
            raise SPSDKValueError("Value not defined")
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value.tag) << 3

    def __repr__(self) -> str:
        return f"{self.__class__.__name__} <{self.ops.label}/{self.num_bytes}, {len(self._data)}>"

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, key: int) -> list[int]:
        return self._data[key]

    def __setitem__(self, key: int, value: list[int]) -> None:
        self._data[key] = value

    def __iter__(self) -> Iterator[list[int]]:
        return self._data.__iter__()

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Write Data Command (Ops: {self.ops.label}, Bytes: {self.num_bytes})\n"
        for cmd in self._data:
            msg += f"- Address: 0x{cmd[0]:08X}, Value: 0x{cmd[1]:08X}\n"
        return msg

    def append(self, address: int, value: int) -> None:
        """Append of Write data command."""
        if address < 0 or address > 0xFFFFFFFF:
            raise SPSDKError("Address out of range")
        if value < 0 or value > 0xFFFFFFFF:
            raise SPSDKError("Value out of range")
        self._data.append([address, value])
        self._header.length += 8

    def pop(self, index: int) -> list[int]:
        """Pop of Write data command."""
        if index < 0 or index >= len(self._data):
            raise SPSDKError("Length of data is incorrect")
        cmd = self._data.pop(index)
        self._header.length -= 8
        return cmd

    def clear(self) -> None:
        """Clear of Write data command."""
        self._data.clear()
        self._header.length = self._header.size

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        for cmd in self._data:
            raw_data += pack(">LL", cmd[0], cmd[1])
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, required_tag=CmdTag.WRT_DAT.tag)
        obj = cls(header.param & 0x7, WriteDataOpsEnum.from_tag((header.param >> 3) & 0x3))
        index = header.size
        while index < header.length:
            (address, value) = unpack_from(">LL", data, index)
            obj.append(address, value)
            index += 8
        return obj
