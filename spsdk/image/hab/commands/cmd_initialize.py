#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB Initialize command implementation for secure boot.

This module provides the CmdInitialize class that implements the HAB (High Assurance Boot)
Initialize command used in NXP's secure boot process for MCU devices.
"""

from struct import pack, unpack_from
from typing import Iterator, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdTag, EngineEnum
from spsdk.image.hab.hab_header import CmdHeader


class CmdInitialize(CmdBase):
    """HAB Initialize command for configuring engine features during ROM exit.

    This command allows initialization of specified engine features when exiting ROM.
    The command contains a tag, length, engine specification, and optional data values.
    It provides list-like interface for managing initialization data.

    Command structure::

    +-------------+--------------+--------------+
    |     tag     |      len     |     eng      |
    +-------------+--------------+--------------+
    |                   [val]                   |
    +-------------------------------------------+
    |                     .                     |
    +-------------------------------------------+

    :cvar CMD_TAG: Command tag identifier for initialize operations.
    """

    CMD_TAG = CmdTag.INIT

    def __init__(
        self, engine: EngineEnum = EngineEnum.ANY, data: Optional[list[int]] = None
    ) -> None:
        """Initialize the HAB Initialize command.

        Creates a new Initialize command instance with the specified engine type
        and optional initialization data.

        :param engine: Engine type for the command, defaults to ANY engine
        :param data: Optional list of initialization data integers
        :raises SPSDKError: When engine parameter has incorrect value
        """
        if engine not in EngineEnum:
            raise SPSDKError("Incorrect value of engine")
        super().__init__(engine.tag)
        self._data = data if data else []

    @property
    def engine(self) -> EngineEnum:
        """Get the engine type from the command header.

        :return: Engine enumeration value extracted from the header parameter.
        """
        return EngineEnum.from_tag(self._header.param)

    @engine.setter
    def engine(self, value: EngineEnum) -> None:
        """Set the engine type for the HAB command.

        This method validates and sets the engine parameter in the command header
        to specify which cryptographic engine should be used.

        :param value: Engine type to be set for the command.
        :raises SPSDKError: If the provided engine value is not valid.
        """
        if value not in EngineEnum:
            raise SPSDKError("Incorrect value of engine")
        self._header.param = value.tag

    def __repr__(self) -> str:
        """Return string representation of the Initialize command.

        The representation includes the class name, engine label, and data length
        for debugging and logging purposes.

        :return: String representation in format "ClassName <engine_label, data_length>".
        """
        return f"{self.__class__.__name__} <{self.engine.label}, {len(self._data)}>"

    def __len__(self) -> int:
        """Get the length of the command data.

        :return: Number of bytes in the command data.
        """
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        """Get data item at specified index.

        Provides access to the internal data array using standard indexing notation.

        :param key: Index position in the data array.
        :raises IndexError: If the index is out of range.
        :return: Data value at the specified index.
        """
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        """Set a value at the specified index in the internal data array.

        This method allows direct assignment of integer values to specific positions
        in the command's internal data structure.

        :param key: Index position in the data array where the value should be set.
        :param value: Integer value to be assigned at the specified index.
        """
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        """Return an iterator over the data bytes.

        Allows iteration over the internal data structure using standard Python
        iteration protocols.

        :return: Iterator yielding individual integer values from the data.
        """
        return self._data.__iter__()

    def __str__(self) -> str:
        """Get text description of the initialize command.

        Returns a formatted string containing the command type, engine description,
        and all initialization data values with their indices in hexadecimal format.

        :return: Formatted string representation of the initialize command.
        """
        msg = super().__str__()
        msg += f"Initialize Command (Engine: {self.engine.description})\n"
        cnt = 0
        for val in self._data:
            msg += f" {cnt:02d}) Value: 0x{val:08X}\n"
            cnt += 1
        return msg

    def append(self, value: int) -> None:
        """Append a value to the Initialize command.

        The method adds a 32-bit value to the command data and updates the header length
        accordingly.

        :param value: 32-bit integer value to append to the command data.
        :raises SPSDKError: If value is out of valid 32-bit unsigned integer range.
        """
        assert isinstance(value, int), "value must be INT type"
        if value < 0 or value >= 0xFFFFFFFF:
            raise SPSDKError("Value out of range")
        self._data.append(value)
        self._header.length += 4

    def pop(self, index: int) -> int:
        """Remove and return element at specified index from Initialize command data.

        Updates the command header length accordingly when an element is removed.

        :param index: Index of element to remove from data list.
        :raises SPSDKError: If index is out of bounds for the data list.
        :return: Value that was removed from the specified index.
        """
        if index < 0 or index >= len(self._data):
            raise SPSDKError("Incorrect length of data")
        val = self._data.pop(index)
        self._header.length -= 4
        return val

    def clear(self) -> None:
        """Clear the Initialize command data.

        Resets the internal data buffer and updates the header length to reflect
        the cleared state.
        """
        self._data.clear()
        self._header.length = self._header.size

    def export(self) -> bytes:
        """Export command to binary form for serialization.

        Converts the command object into its binary representation by calling the parent
        export method and appending all data values as big-endian 32-bit unsigned integers.

        :return: Binary representation of the command ready for transmission or storage.
        """
        raw_data = super().export()
        for val in self._data:
            raw_data += pack(">L", val)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into Initialize command object.

        Deserializes binary representation of HAB Initialize command back into
        a command object instance.

        :param data: Binary data to be parsed into command object.
        :raises SPSDKError: If incorrect length of data.
        :return: Parsed Initialize command object.
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
