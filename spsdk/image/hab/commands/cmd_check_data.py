#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB Check Data command implementation.

This module implements the Check Data command for High Assurance Boot (HAB),
providing functionality to verify data integrity during the boot process.
"""

from struct import pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.commands.commands import CmdBase
from spsdk.image.hab.constants import CmdTag
from spsdk.image.hab.hab_header import CmdHeader
from spsdk.utils.spsdk_enum import SpsdkEnum


class CheckDataOpsEnum(SpsdkEnum):
    """HAB Check Data operation types enumeration.

    This enumeration defines the available operation types for the HAB Check Data
    command 'par' parameter, specifying different bit checking modes for data
    validation operations.
    """

    ALL_CLEAR = (0, "ALL_CLEAR", "All bits clear")
    ALL_SET = (1, "ALL_SET", "All bits set")
    ANY_CLEAR = (2, "ANY_CLEAR", "Any bit clear")
    ANY_SET = (3, "ANY_SET", "Any bit set")


class CmdCheckData(CmdBase):
    """HAB Check Data command for memory validation operations.

    This class represents a HAB (High Assurance Boot) command that tests memory locations
    against specified bit masks. It supports 1, 2, or 4-byte operations and can validate
    data at given addresses using configurable masks and optional count parameters.
    The command structure includes address, mask, and optional count fields as shown
    in the binary layout diagram.

    +-------------+--------------+--------------+
    |     tag     |      len     |     par      |
    +-------------+--------------+--------------+
    |                  address                  |
    +-------------------------------------------+
    |                    mask                   |
    +-------------------------------------------+
    |                  [count]                  |
    +-------------------------------------------+

    :cvar CMD_TAG: Command tag identifier for check data operations.
    """

    CMD_TAG = CmdTag.CHK_DAT

    def __init__(
        self,
        numbytes: int = 4,
        ops: CheckDataOpsEnum = CheckDataOpsEnum.ALL_SET,
        address: int = 0,
        mask: int = 0,
        count: Optional[int] = None,
    ) -> None:
        """Initialize the check data command.

        Creates a HAB check data command with specified parameters for memory verification
        operations.

        :param numbytes: Number of bytes to check (must be 1, 2, or 4).
        :param ops: Type of check operation to perform.
        :param address: Memory address to check.
        :param mask: Mask value for the check operation.
        :param count: Optional count value for repeated operations.
        :raises SPSDKError: If incorrect number of bytes (not 1, 2, or 4).
        :raises SPSDKError: If incorrect operation type.
        """
        if numbytes not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        if ops not in CheckDataOpsEnum:
            raise SPSDKError("Incorrect operation")
        super().__init__(((int(ops.tag) & 0x3) << 3) | (numbytes & 0x7))
        self.address = address
        self.mask = mask
        self.count = count
        # the length of 'address'(4B), 'mask'(4B) and count(0 or 4B)  need to be added into Header.length
        self._header.length += 4 + 4 + (4 if count else 0)

    @property
    def num_bytes(self) -> int:
        """Get the number of bytes from the header parameter.

        Extracts the lower 3 bits from the header parameter field to determine
        the number of bytes value.

        :return: Number of bytes as extracted from header parameter (0-7 range).
        """
        return self._header.param & 0x7

    @num_bytes.setter
    def num_bytes(self, value: int) -> None:
        """Set the number of bytes for data checking operation.

        Configures the parameter field in the header to specify how many bytes
        should be processed during the data check operation.

        :param value: Number of bytes to check, must be 1, 2, or 4.
        :raises SPSDKError: If value is not 1, 2, or 4.
        """
        if value not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        self._header.param &= ~0x7
        self._header.param |= int(value)

    @property
    def ops(self) -> CheckDataOpsEnum:
        """Get operation of Check data command.

        :return: Operation type extracted from the command header parameter bits.
        """
        return CheckDataOpsEnum.from_tag((self._header.param >> 3) & 0x3)

    @ops.setter
    def ops(self, value: CheckDataOpsEnum) -> None:
        """Set the operation type for Check data command.

        The method configures the operation field in the command header by clearing
        the existing operation bits and setting new ones based on the provided value.

        :param value: Operation type to be set for the check data command.
        :raises SPSDKError: If incorrect operation type is provided.
        """
        if value not in CheckDataOpsEnum:
            raise SPSDKError("Incorrect operation")
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value.tag) << 3

    def __repr__(self) -> str:
        """Return string representation of the CheckData command.

        The representation includes the class name, operation label, number of bytes,
        address, and mask in hexadecimal format.

        :return: String representation of the CheckData command object.
        """
        return (
            f"{self.__class__.__name__} <{self.ops.label}/{self.num_bytes}, "
            f"ADDR=0x{self.address:X}, MASK=0x{self.mask:X}>"
        )

    def __str__(self) -> str:
        """Get text description of the Check Data command.

        Provides a formatted string representation of the Check Data command including
        operation type, number of bytes, address, mask, and optional count parameters.

        :return: Formatted string description of the command.
        """
        msg = super().__str__()
        msg += f"Check Data Command (Ops: {self.ops.label}, Bytes: {self.num_bytes})\n"

        msg += f"- Address: 0x{self.address:08X}, Mask: 0x{self.mask:08X}"
        if self.count:
            msg += f", Count: {self.count}"
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export command to binary representation.

        Serializes the command data including address, mask, and optional count
        into binary format suitable for HAB processing.

        :return: Binary representation of the command as bytes.
        """
        raw_data = super().export()
        raw_data += pack(">LL", self.address, self.mask)
        if self.count is not None:
            raw_data += pack(">L", self.count)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into CheckData command object.

        Deserializes binary representation of a CheckData command by extracting
        header information, operation parameters, address, mask, and optional count.

        :param data: Binary data to be parsed into command object.
        :return: Parsed CheckData command instance.
        """
        header = CmdHeader.parse(data, CmdTag.CHK_DAT.tag)
        numbytes = header.param & 0x7
        ops = (header.param >> 3) & 0x3
        address, mask = unpack_from(">LL", data, header.size)
        count = None
        if (header.length - header.size) > 8:
            count = unpack_from(">L", data, header.size + 8)[0]
        return cls(numbytes, CheckDataOpsEnum.from_tag(ops), address, mask, count)
