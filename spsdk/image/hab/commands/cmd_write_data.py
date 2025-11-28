#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB Write Data command implementation.

This module provides functionality for creating and managing HAB Write Data commands,
which are used to write specific values to memory addresses during secure boot operations.
The module includes command operations enumeration and the main WriteData command class.
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
    """HAB Write Data command operation flags enumeration.

    This enumeration defines the available operation types for the Write Data command
    in HAB (High Assurance Boot) context, controlling how data is written to memory
    locations through different bitwise operations.
    """

    WRITE_VALUE = (0, "WRITE_VALUE", "Write value")
    WRITE_CLEAR_BITS = (1, "WRITE_CLEAR_BITS", "Write clear bits")
    CLEAR_BITMASK = (2, "CLEAR_BITMASK", "Clear bitmask")
    SET_BITMASK = (3, "SET_BITMASK", "Set bitmask")


class CmdWriteData(CmdBase):
    """HAB Write Data command for memory operations.

    This command enables writing data to specific memory addresses with configurable
    byte width and operation types. It supports multiple address-value pairs in a
    single command and provides different write operation modes.

    Write data command::

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

    :cvar CMD_TAG: Command tag identifier for Write Data operations.

    """

    CMD_TAG = CmdTag.WRT_DAT

    def __init__(
        self,
        numbytes: int = 4,
        ops: WriteDataOpsEnum = WriteDataOpsEnum.WRITE_VALUE,
        data: Optional[Iterable[tuple[int, int]]] = None,
    ) -> None:
        """Initialize Write Data command.

        Creates a new Write Data command with specified byte width, operation type, and optional data.

        :param numbytes: Number of bytes per operation. Must be 1, 2, or 4.
        :param ops: Type of write operation to perform.
        :param data: Optional list of tuples containing (address, value) pairs to write.
        :raises SPSDKError: When numbytes is not 1, 2, or 4.
        :raises SPSDKError: When ops is not a valid WriteDataOpsEnum value.
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
        """Number of bytes being written by the command.

        :return: Number of bytes extracted from the command header parameter (lower 3 bits).
        """
        return self._header.param & 0x7

    @num_bytes.setter
    def num_bytes(self, value: int) -> None:
        """Set number of bytes being written by the command.

        :param value: Number of bytes being written by the command (must be 1, 2, or 4)
        :raises SPSDKError: When number of bytes is not 1, 2 nor 4
        """
        if value not in (1, 2, 4):
            raise SPSDKError("number of bytes is not 1, 2 nor 4")
        self._header.param &= ~0x7
        self._header.param |= value

    @property
    def ops(self) -> WriteDataOpsEnum:
        """Get the type of write operation.

        Extracts and returns the write operation type from the command header by
        parsing the parameter field bits 3-4.

        :return: The write operation type enumeration value.
        """
        return WriteDataOpsEnum.from_tag((self._header.param >> 3) & 0x3)

    @ops.setter
    def ops(self, value: WriteDataOpsEnum) -> None:
        """Set write data operation type.

        This method configures the operation type for the write data command by updating
        the appropriate bits in the header parameter field.

        :param value: The write data operation type to set.
        :raises SPSDKValueError: If the provided value is not a valid WriteDataOpsEnum.
        """
        if value not in WriteDataOpsEnum:
            raise SPSDKValueError("Value not defined")
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value.tag) << 3

    def __repr__(self) -> str:
        """Return string representation of WriteData command.

        The representation includes the class name, operation label, number of bytes,
        and actual data length for debugging and logging purposes.

        :return: String representation in format 'WriteData <ops_label/num_bytes, data_length>'.
        """
        return f"{self.__class__.__name__} <{self.ops.label}/{self.num_bytes}, {len(self._data)}>"

    def __len__(self) -> int:
        """Get the length of the write data command.

        :return: Number of bytes in the data payload.
        """
        return len(self._data)

    def __getitem__(self, key: int) -> list[int]:
        """Get data item at specified index.

        Retrieves a list of integers from the internal data storage at the given index position.

        :param key: Index position to retrieve data from.
        :return: List of integers at the specified index.
        """
        return self._data[key]

    def __setitem__(self, key: int, value: list[int]) -> None:
        """Set data value at specified key index.

        :param key: Index position in the data structure.
        :param value: List of integer values to store at the specified key.
        """
        self._data[key] = value

    def __iter__(self) -> Iterator[list[int]]:
        """Return iterator over the data chunks.

        Provides an iterator interface to iterate through the internal data structure,
        yielding lists of integers representing data chunks.

        :return: Iterator yielding lists of integers from the internal data structure.
        """
        return self._data.__iter__()

    def __str__(self) -> str:
        """Get string representation of the Write Data command.

        Provides a formatted text description including operation type, number of bytes,
        and detailed list of all address-value pairs to be written.

        :return: Formatted string describing the command with operation details and data pairs.
        """
        msg = super().__str__()
        msg += f"Write Data Command (Ops: {self.ops.label}, Bytes: {self.num_bytes})\n"
        for cmd in self._data:
            msg += f"- Address: 0x{cmd[0]:08X}, Value: 0x{cmd[1]:08X}\n"
        return msg

    def append(self, address: int, value: int) -> None:
        """Append address-value pair to write data command.

        Adds a new address-value pair to the write data command list and updates
        the command header length accordingly.

        :param address: Memory address to write to (0x0 to 0xFFFFFFFF).
        :param value: Value to write at the specified address (0x0 to 0xFFFFFFFF).
        :raises SPSDKError: Address or value is out of valid range.
        """
        if address < 0 or address > 0xFFFFFFFF:
            raise SPSDKError("Address out of range")
        if value < 0 or value > 0xFFFFFFFF:
            raise SPSDKError("Value out of range")
        self._data.append([address, value])
        self._header.length += 8

    def pop(self, index: int) -> list[int]:
        """Remove a write data command at the specified index.

        This method removes a command from the internal data list and updates
        the header length accordingly.

        :param index: Index of the command to remove from the data list.
        :raises SPSDKError: If the index is out of range.
        :return: The removed command as a list of integers.
        """
        if index < 0 or index >= len(self._data):
            raise SPSDKError("Length of data is incorrect")
        cmd = self._data.pop(index)
        self._header.length -= 8
        return cmd

    def clear(self) -> None:
        """Clear the write data command.

        Removes all data from the command and resets the header length to the base header size.
        """
        self._data.clear()
        self._header.length = self._header.size

    def export(self) -> bytes:
        """Export command to binary form (serialization).

        Converts the write data command and its associated data pairs into a binary
        representation suitable for HAB processing.

        :return: Binary representation of the command including all address-data pairs.
        """
        raw_data = super().export()
        for cmd in self._data:
            raw_data += pack(">LL", cmd[0], cmd[1])
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into WriteData command object.

        Deserializes binary representation of a WriteData command by parsing the header
        and extracting address-value pairs from the data payload.

        :param data: Binary data to be parsed into command object.
        :return: Parsed WriteData command instance.
        """
        header = CmdHeader.parse(data, required_tag=CmdTag.WRT_DAT.tag)
        obj = cls(header.param & 0x7, WriteDataOpsEnum.from_tag((header.param >> 3) & 0x3))
        index = header.size
        while index < header.length:
            (address, value) = unpack_from(">LL", data, index)
            obj.append(address, value)
            index += 8
        return obj
