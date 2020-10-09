#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""File including helping functions."""

from abc import abstractmethod
from struct import calcsize, pack, unpack_from
from typing import Tuple

from spsdk.sbfile.sb31.constants import EnumCmdTag


def add_leading_zeros(byte_data: bytes, return_size: int) -> bytes:
    """Return data with leading zeros.

    :param byte_data: Input data as bytes array
    :param return_size:
    :return: bytes
    """
    padding_size = return_size - len(byte_data)
    byte_data_with_padding = bytes("\x00" * padding_size, "utf8") + byte_data
    return byte_data_with_padding


def add_trailing_zeros(byte_data: bytes, return_size: int) -> bytes:
    """Return data with trailing zeros.

    :param byte_data: Input data as bytes array
    :param return_size:
    :return: bytes
    """
    size_of_zeros = return_size - len(byte_data)
    byte_data_with_padding = byte_data + bytes("\x00" * size_of_zeros, "utf8")
    return byte_data_with_padding


class MainCmd:
    """Functions for creating cmd intended for inheritance."""

    def __eq__(self, obj: object) -> bool:
        """Comparison of values."""
        return isinstance(obj, self.__class__) and vars(obj) == vars(self)

    def __str__(self) -> str:
        """Get info of command."""
        return self.info()

    @abstractmethod
    def info(self) -> str:
        """Get info of command."""
        raise NotImplementedError("Info must be implemented in the derived class.")

    def export(self) -> bytes:
        """Export command as bytes."""
        raise NotImplementedError("Export must be implemented in the derived class.")

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> object:
        """Parse command from bytes array."""
        raise NotImplementedError("Parse must be implemented in the derived class.")


class BaseCmd(MainCmd):
    """Functions for creating cmd intended for inheritance."""
    FORMAT = "<4L"
    SIZE = calcsize(FORMAT)
    TAG = 0x55aaaa55

    @property
    def address(self) -> int:
        """Get address."""
        return self._address

    @address.setter
    def address(self, value: int) -> None:
        """Set address."""
        assert 0x00000000 <= value <= 0xFFFFFFFF
        self._address = value

    @property
    def length(self) -> int:
        """Get length."""
        return self._length

    @length.setter
    def length(self, value: int) -> None:
        """Set value."""
        assert 0x00000000 <= value <= 0xFFFFFFFF
        self._length = value

    def __init__(self, address: int, length: int, cmd_tag: int = EnumCmdTag.NONE) -> None:
        """Constructor for Commands header.

        :param address: Input address
        :param length: Input length
        :param cmd_tag: Command tag
        """
        self._address = address
        self._length = length
        self.cmd_tag = cmd_tag

    def info(self) -> str:
        """Get info of command."""
        raise NotImplementedError("Info must be implemented in the derived class.")

    def export(self) -> bytes:
        """Export command header as bytes array."""
        return pack(self.FORMAT, self.TAG, self.address, self.length, self.cmd_tag)

    @classmethod
    def header_parse(cls, cmd_tag: int, data: bytes, offset: int = 0) -> Tuple[int, int]:
        """Parse header command from bytes array.

        :param data: Input data as bytes array
        :param offset: The offset of input data
        :param cmd_tag: Information about command tag
        :raises ValueError: Raise if tag is not equal to required TAG
        :raises ValueError: Raise if cmd is not equal EnumCmdTag
        :return: Tuple
        """
        tag, address, length, cmd = unpack_from(cls.FORMAT, data, offset)
        if tag != cls.TAG:
            raise ValueError("TAG is not valid.")
        if cmd != cmd_tag:
            raise ValueError("Values are not same.")
        return address, length
