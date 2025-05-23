#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB Check Data command implementation.

This module implements the Check Data command for High Assurance Boot (HAB).
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
    """Enum definition for 'par' parameter of Check Data command."""

    ALL_CLEAR = (0, "ALL_CLEAR", "All bits clear")
    ALL_SET = (1, "ALL_SET", "All bits set")
    ANY_CLEAR = (2, "ANY_CLEAR", "Any bit clear")
    ANY_SET = (3, "ANY_SET", "Any bit set")


class CmdCheckData(CmdBase):
    """Check data command. Test for a given 1, 2 or 4-byte bitmask from a source address.

    +-------------+--------------+--------------+
    |     tag     |      len     |     par      |
    +-------------+--------------+--------------+
    |                  address                  |
    +-------------------------------------------+
    |                    mask                   |
    +-------------------------------------------+
    |                  [count]                  |
    +-------------------------------------------+
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

        :param numbytes: number of bytes
        :param ops: type of  operation
        :param address: list of tuples: address and value
        :param mask: mask value
        :param count: count value
        :raises SPSDKError: If incorrect number of bytes
        :raises SPSDKError: If incorrect operation
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
        """Number of bytes."""
        return self._header.param & 0x7

    @num_bytes.setter
    def num_bytes(self, value: int) -> None:
        if value not in (1, 2, 4):
            raise SPSDKError("Incorrect number of bytes")
        self._header.param &= ~0x7
        self._header.param |= int(value)

    @property
    def ops(self) -> CheckDataOpsEnum:
        """Operation of Check data command."""
        return CheckDataOpsEnum.from_tag((self._header.param >> 3) & 0x3)

    @ops.setter
    def ops(self, value: CheckDataOpsEnum) -> None:
        """Operation of Check data command.

        :raises SPSDKError: If incorrect operation
        """
        if value not in CheckDataOpsEnum:
            raise SPSDKError("Incorrect operation")
        self._header.param &= ~(0x3 << 3)
        self._header.param |= int(value.tag) << 3

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__} <{self.ops.label}/{self.num_bytes}, "
            f"ADDR=0x{self.address:X}, MASK=0x{self.mask:X}>"
        )

    def __str__(self) -> str:
        """Text description of the command."""
        msg = super().__str__()
        msg += f"Check Data Command (Ops: {self.ops.label}, Bytes: {self.num_bytes})\n"

        msg += f"- Address: 0x{self.address:08X}, Mask: 0x{self.mask:08X}"
        if self.count:
            msg += f", Count: {self.count}"
        msg += "\n"
        return msg

    def export(self) -> bytes:
        """Export to binary form (serialization).

        :return: binary representation of the command
        """
        raw_data = super().export()
        raw_data += pack(">LL", self.address, self.mask)
        if self.count is not None:
            raw_data += pack(">L", self.count)
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Convert binary representation into command (deserialization from binary data).

        :param data: being parsed
        :return: parse command
        """
        header = CmdHeader.parse(data, CmdTag.CHK_DAT.tag)
        numbytes = header.param & 0x7
        ops = (header.param >> 3) & 0x3
        address, mask = unpack_from(">LL", data, header.size)
        count = None
        if (header.length - header.size) > 8:
            count = unpack_from(">L", data, header.size + 8)[0]
        return cls(numbytes, CheckDataOpsEnum.from_tag(ops), address, mask, count)
