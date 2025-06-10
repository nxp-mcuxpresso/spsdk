#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module containing definitions for HAB (High Assurance Boot) headers."""
from struct import calcsize, pack, unpack_from
from typing import Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.hab.constants import CmdTag
from spsdk.utils.abstract import BaseClass
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier


class SegmentTag(SpsdkEnum):
    """Segments Tag."""

    XMCD = (0xC0, "XMCD", "External Memory Configuration Data")
    DCD = (0xD2, "DCD", "Device Configuration Data")
    CSF = (0xD4, "CSF", "Command Sequence File Data")
    IVT = (0xD1, "IVT2", "Image Vector Table (Version 2)")
    CRT = (0xD7, "CRT", "Certificate")
    SIG = (0xD8, "SIG", "Signature")
    EVT = (0xDB, "EVT", "Event")
    RVT = (0xDD, "RVT", "ROM Vector Table")
    WRP = (0x81, "WRP", "Wrapped Key")
    MAC = (0xAC, "MAC", "Message Authentication Code")
    IVT3 = (0xDE, "IVT3", "Image Vector Table (Version 3)")
    BIC1 = (0x87, "BIC1", "Boot Images Container")
    SIGB = (0x90, "SIGB", "Signature block")


class Header(BaseClass):
    """Header element type."""

    FORMAT = ">BHB"
    SIZE = calcsize(FORMAT)

    @property
    def size(self) -> int:
        """Header size in bytes."""
        return self.SIZE

    def __init__(self, tag: int = 0, param: int = 0, length: Optional[int] = None) -> None:
        """Header initialization.

        :param tag: Section tag
        :param param: Parameters
        :param length: Length of the binary; if not specified, size of the header is used
        """
        self._tag = tag
        self.param: int = param
        self.length: int = self.SIZE if length is None else length

    def verify(self) -> Verifier:
        """Verify header data."""
        ret = Verifier("Header")
        ret.add_record_range("Header length", value=self.length, min_val=self.SIZE, max_val=65536)
        return ret

    @property
    def tag(self) -> int:
        """Returns tag of a command or segment."""
        return self._tag

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.param}, {self.length})"

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} <TAG:0x{self.tag:02X}, "
            f"PARAM:0x{self.param:02X}, LEN:{self.length}B>"
        )

    def export(self) -> bytes:
        """Binary representation of the header."""
        return pack(self.FORMAT, self.tag, self.length, self.param)

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Parse header.

        :param data: Raw data as bytes or bytearray
        :param required_tag: Check header tag if specified value or ignore if is None
        :return: Header object
        :raises SPSDKParsingError: if required header tag does not match
        """
        if len(data) < cls.SIZE:
            raise SPSDKParsingError(
                f"Invalid input data size for {cls.__name__}: ({len(data)} < {cls.SIZE})."
            )
        tag, length, param = unpack_from(cls.FORMAT, data)

        if required_tag is not None and tag != required_tag:
            raise SPSDKParsingError(
                f"Invalid header tag: '0x{tag:02X}' expected '0x{required_tag:02X}' "
            )

        return cls(tag, param, length)

    @property
    def version_major(self) -> int:
        """Major format version."""
        return self.param >> 4

    @property
    def version_minor(self) -> int:
        """Minor format version."""
        return self.param & 0xF


class CmdHeader(Header):
    """Command header."""

    def __init__(
        self, tag: Union[CmdTag, int], param: int = 0, length: Optional[int] = None
    ) -> None:
        """Command header initialization.

        :param tag: command tag
        :param param: Command parameters
        :param length: of the command binary section, in bytes
        :raises SPSDKError: If invalid command tag
        """
        tag = tag.tag if isinstance(tag, CmdTag) else tag
        if tag not in CmdTag.tags():
            raise SPSDKError("Invalid command tag")
        super().__init__(tag, param, length)

    @property
    def tag_name(self) -> str:
        """Returns the header's tag name."""
        return CmdTag.get_label(self.tag)

    def verify(self) -> Verifier:
        """Verify header data."""
        ret = Verifier("Command Header")
        ret.add_child(super().verify())
        ret.add_record_enum("Header tag", value=self.length, enum=CmdTag)
        return ret

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Parse header.

        :param data: Raw data as bytes or bytearray
        :param required_tag: Check header tag if specified value or ignore if is None
        :return: Header object
        :raises SPSDKError: If required header tag does not exist
        """
        if required_tag is not None:
            if required_tag not in CmdTag.tags():
                raise SPSDKError("Invalid tag")
        return super().parse(data, required_tag)
