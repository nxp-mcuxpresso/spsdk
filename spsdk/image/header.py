#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Header."""

from struct import calcsize, pack, unpack_from
from typing import Optional

from spsdk import SPSDKError
from spsdk.utils.easy_enum import Enum

########################################################################################################################
# Enums
########################################################################################################################


class SegTag(Enum):
    """Segments Tag."""

    DCD = (0xD2, "Device Configuration Data")
    CSF = (0xD4, "Command Sequence File Data")
    # i.MX6, i.MX7, i.MX8M
    IVT2 = (0xD1, "Image Vector Table (Version 2)")
    CRT = (0xD7, "Certificate")
    SIG = (0xD8, "Signature")
    EVT = (0xDB, "Event")
    RVT = (0xDD, "ROM Vector Table")
    WRP = (0x81, "Wrapped Key")
    MAC = (0xAC, "Message Authentication Code")
    # i.MX8QXP_A0, i.MX8QM_A0
    IVT3 = (0xDE, "Image Vector Table (Version 3)")
    # i.MX8QXP_B0, i.MX8QM_B0
    BIC1 = (0x87, "Boot Images Container")
    SIGB = (0x90, "Signature block")


class CmdTag(Enum):
    """CSF/DCD Command Tag."""

    SET = (0xB1, "Set")
    INS_KEY = (0xBE, "Install Key")
    AUT_DAT = (0xCA, "Authenticate Data")
    WRT_DAT = (0xCC, "Write Data")
    CHK_DAT = (0xCF, "Check Data")
    NOP = (0xC0, "No Operation (NOP)")
    INIT = (0xB4, "Initialize")
    UNLK = (0xB2, "Unlock")


########################################################################################################################
# Exceptions
########################################################################################################################


class UnparsedException(Exception):
    """Unparsed Exception."""


class CorruptedException(Exception):
    """Corrupted Exception."""


########################################################################################################################
# Classes
########################################################################################################################


class Header:
    """Header element type."""

    FORMAT = ">BHB"
    SIZE = calcsize(FORMAT)

    @property
    def size(self) -> int:
        """Header size in bytes."""
        return self.SIZE

    def __init__(self, tag: int = 0, param: int = 0, length: Optional[int] = None) -> None:
        """Constructor.

        :param tag: section tag
        :param param: TODO
        :param length: length of the segment or command; if not specified, size of the header is used
        :raises SPSDKError: If invalid length
        """
        self._tag = tag
        self.param: int = param
        self.length: int = self.SIZE if length is None else length
        if self.SIZE > self.length or self.length >= 65536:
            raise SPSDKError("Invalid length")

    @property
    def tag(self) -> int:
        """:return: section tag: command tag or segment tag, ..."""
        return self._tag

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.tag}, {self.param}, {self.length})"

    def __str__(self) -> str:
        return f"{self.__class__.__name__} <TAG:0x{self.tag:02X}, PARAM:0x{self.param:02X}, LEN:{self.length}B>"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def info(self) -> str:
        """Text representation of the header."""
        return str(self)

    def export(self) -> bytes:
        """Binary representation of the header."""
        return pack(self.FORMAT, self.tag, self.length, self.param)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0, required_tag: Optional[int] = None) -> "Header":
        """Parse header.

        :param data: Raw data as bytes or bytearray
        :param offset: Offset of input data
        :param required_tag: Check header TAG if specified value or ignore if is None
        :return: Header object
        :raise UnparsedException: if required header tag does not match
        """
        tag, length, param = unpack_from(cls.FORMAT, data, offset)
        if required_tag is not None and tag != required_tag:
            raise UnparsedException(
                " Invalid header tag: '0x{:02X}' expected '0x{:02X}' ".format(tag, required_tag)
            )

        return cls(tag, param, length)


class CmdHeader(Header):
    """Command header."""

    def __init__(self, tag: CmdTag, param: int = 0, length: Optional[int] = None) -> None:
        """Constructor.

        :param tag: command tag
        :param param: TODO
        :param length: of the command binary section, in bytes
        :raises SPSDKError: If invalid command tag
        """
        super().__init__(tag, param, length)
        if tag not in CmdTag.tags():
            raise SPSDKError("Invalid command tag")

    @property
    def tag(self) -> CmdTag:
        """Command tag."""
        return CmdTag.from_int(self._tag)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0, required_tag: Optional[int] = None) -> Header:
        """Create Header from binary data.

        :param data: binary data to convert into header
        :param offset: to start reading binary data
        :param required_tag: CmdTag, None if not required
        :return: parsed instance
        :raises UnparsedException: if required header tag does not match
        :raises SPSDKError: If invalid tag
        """
        if required_tag is not None:
            if required_tag not in CmdTag.tags():
                raise SPSDKError("Invalid tag")
        return super(CmdHeader, cls).parse(data, offset, required_tag)


class Header2(Header):
    """Header element type."""

    FORMAT = "<BHB"

    def export(self) -> bytes:
        """Binary representation of the header."""
        return pack(self.FORMAT, self.param, self.length, self.tag)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0, required_tag: int = None) -> "Header":
        """Parse header.

        :param data: Raw data as bytes or bytearray
        :param offset: Offset of input data
        :param required_tag: Check header TAG if specified value or ignore if is None
        :raises UnparsedException: Raises an error if required tag is empty or not valid
        :return: Header2 object
        """
        param, length, tag = unpack_from(cls.FORMAT, data, offset)
        if required_tag is not None and tag != required_tag:
            raise UnparsedException(
                " Invalid header tag: '0x{:02X}' expected '0x{:02X}' ".format(tag, required_tag)
            )

        return cls(tag, param, length)
