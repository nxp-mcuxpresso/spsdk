#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB header definitions and utilities.

This module provides classes for handling High Assurance Boot (HAB) headers,
including segment tags, command headers, and general header structures used
in NXP's HAB security framework.
"""

from struct import calcsize, pack, unpack_from
from typing import Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.hab.constants import CmdTag
from spsdk.utils.abstract import BaseClass
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier


class SegmentTag(SpsdkEnum):
    """HAB segment tag enumeration for image processing.

    This enumeration defines the standard HAB (High Assurance Boot) segment tags
    used to identify different types of data segments in secure boot images.
    Each tag contains a numeric identifier, short name, and descriptive label
    for the corresponding segment type.
    """

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
    """HAB (High Assurance Boot) header element for secure boot operations.

    This class represents a binary header structure used in NXP's HAB security
    framework. It manages header data including tag identification, parameters,
    and length information for various HAB commands and segments.

    :cvar FORMAT: Binary format string for header structure packing.
    :cvar SIZE: Fixed size of the header in bytes.
    """

    FORMAT = ">BHB"
    SIZE = calcsize(FORMAT)

    @property
    def size(self) -> int:
        """Get header size in bytes.

        :return: Size of the header in bytes.
        """
        return self.SIZE

    def __init__(self, tag: int = 0, param: int = 0, length: Optional[int] = None) -> None:
        """Initialize HAB header with tag, parameters and length.

        :param tag: Section tag identifier for the HAB header.
        :param param: Additional parameters for the header configuration.
        :param length: Length of the binary data; if not specified, header size is used as default.
        """
        self._tag = tag
        self.param: int = param
        self.length: int = self.SIZE if length is None else length

    def verify(self) -> Verifier:
        """Verify header data and validate its properties.

        The method creates a verifier object to check header length constraints
        and ensure the header data meets HAB (High Assurance Boot) requirements.

        :return: Verifier object containing validation results for the header.
        """
        ret = Verifier("Header")
        ret.add_record_range("Header length", value=self.length, min_val=self.SIZE, max_val=65536)
        return ret

    @property
    def tag(self) -> int:
        """Get tag of a command or segment.

        :return: Tag value as integer.
        """
        return self._tag

    def __repr__(self) -> str:
        """Return string representation of the HAB header object.

        Provides a readable string format showing the class name along with its
        parameter and length values for debugging and logging purposes.

        :return: String representation in format 'ClassName(param, length)'.
        """
        return f"{self.__class__.__name__}({self.param}, {self.length})"

    def __str__(self) -> str:
        """Return string representation of HAB header.

        Provides a formatted string containing the class name, tag value in hexadecimal,
        parameter value in hexadecimal, and length in bytes.

        :return: Formatted string representation of the HAB header.
        """
        return (
            f"{self.__class__.__name__} <TAG:0x{self.tag:02X}, "
            f"PARAM:0x{self.param:02X}, LEN:{self.length}B>"
        )

    def export(self) -> bytes:
        """Export header as binary data.

        Converts the header structure into its binary representation using the defined format.

        :return: Binary representation of the header containing tag, length, and param fields.
        """
        return pack(self.FORMAT, self.tag, self.length, self.param)

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Parse header from binary data.

        The method parses binary data to extract header information including tag, length, and parameter values.
        Optionally validates the header tag against an expected value.

        :param data: Raw data as bytes or bytearray to parse.
        :param required_tag: Expected header tag value for validation, or None to skip validation.
        :return: Header object created from parsed data.
        :raises SPSDKParsingError: If input data is too small or header tag doesn't match required value.
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
        """Get major format version from header.

        :return: Major version number extracted from the upper 4 bits of param field.
        """
        return self.param >> 4

    @property
    def version_minor(self) -> int:
        """Get minor format version from header.

        :return: Minor version number (0-15) extracted from the lower 4 bits of param field.
        """
        return self.param & 0xF


class CmdHeader(Header):
    """HAB command header for secure boot operations.

    This class represents a command header used in NXP's High Assurance Boot (HAB)
    protocol. It extends the base Header class to provide command-specific functionality
    including tag validation, parsing, and verification for HAB command structures.
    """

    def __init__(
        self, tag: Union[CmdTag, int], param: int = 0, length: Optional[int] = None
    ) -> None:
        """Initialize command header with tag, parameters and length.

        Validates the command tag and creates a new command header instance with the
        specified parameters.

        :param tag: Command tag identifier, either CmdTag enum or integer value
        :param param: Command parameters value
        :param length: Length of the command binary section in bytes
        :raises SPSDKError: If invalid command tag is provided
        """
        tag = tag.tag if isinstance(tag, CmdTag) else tag
        if tag not in CmdTag.tags():
            raise SPSDKError("Invalid command tag")
        super().__init__(tag, param, length)

    @property
    def tag_name(self) -> str:
        """Get the header's tag name.

        :return: String representation of the header's tag name.
        """
        return CmdTag.get_label(self.tag)

    def verify(self) -> Verifier:
        """Verify header data and return verification results.

        Creates a verifier object that validates the command header structure,
        including parent class verification and header tag validation against
        the CmdTag enumeration.

        :return: Verifier object containing validation results and any issues found.
        """
        ret = Verifier("Command Header")
        ret.add_child(super().verify())
        ret.add_record_enum("Header tag", value=self.length, enum=CmdTag)
        return ret

    @classmethod
    def parse(cls, data: bytes, required_tag: Optional[int] = None) -> Self:
        """Parse header from raw binary data.

        The method validates the header tag if specified and delegates to parent class parsing.

        :param data: Raw data as bytes or bytearray
        :param required_tag: Check header tag if specified value or ignore if is None
        :return: Header object
        :raises SPSDKError: If required header tag does not exist
        """
        if required_tag is not None:
            if required_tag not in CmdTag.tags():
                raise SPSDKError("Invalid tag")
        return super().parse(data, required_tag)
