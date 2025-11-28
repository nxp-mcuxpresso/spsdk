#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB signature management utilities.

This module provides functionality for creating, manipulating, and exporting HAB (High Assurance Boot)
signatures used in secure boot processes for NXP devices.
"""

from typing import Iterator, Optional, Union

from typing_extensions import Self

from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.utils.abstract import BaseClass


class Signature(BaseClass):
    """HAB signature container for cryptographic operations.

    This class manages signature data used in High Assurance Boot (HAB) operations
    for NXP MCU devices. It provides functionality for creating, storing, and
    manipulating cryptographic signatures with proper HAB formatting including
    headers and data management.
    """

    def __init__(self, version: int = 0x40, data: Optional[bytes] = None) -> None:
        """Initialize HAB signature object.

        :param version: Version of the signature format, defaults to 0x40
        :param data: Raw signature data bytes, defaults to None
        """
        self._header = Header(tag=SegmentTag.SIG.tag, param=version)
        self._data = bytearray() if data is None else bytearray(data)

    @property
    def size(self) -> int:
        """Get the total size of a signature including header.

        :return: Size in bytes.
        """
        return Header.SIZE + len(self._data)

    def __len__(self) -> int:
        """Get length of signature data.

        :return: Length of signature data in bytes.
        """
        return len(self._data)

    def __getitem__(self, key: int) -> int:
        """Access signature data by index.

        :param key: Index to access in the signature data.
        :raises IndexError: If the index is out of range.
        :return: Byte value at the specified index.
        """
        return self._data[key]

    def __setitem__(self, key: int, value: int) -> None:
        """Set signature data at specific index.

        :param key: Index to modify
        :param value: Value to set
        """
        self._data[key] = value

    def __iter__(self) -> Iterator[int]:
        """Get iterator over signature data.

        :return: Iterator over signature data bytes.
        """
        return self._data.__iter__()

    def __repr__(self) -> str:
        """Get string representation for debugging.

        Returns a formatted string containing the signature version and data size
        for debugging and logging purposes.

        :return: String representation with version and size information.
        """
        return f"Signature <Ver: {self._header.version_major}.{self._header.version_minor}, Size: {len(self._data)}>"

    def __str__(self) -> str:
        """Get human-readable string representation of the signature.

        The method creates a formatted string containing signature version information
        and data size, enclosed in decorative separator lines.

        :return: Formatted string representation of the signature.
        """
        msg = "-" * 60 + "\n"
        msg += f"Signature (Ver: {self._header.version_major}.{self._header.version_minor}, Size: {len(self._data)})\n"
        msg += "-" * 60 + "\n"
        return msg

    @property
    def data(self) -> bytes:
        """Get signature data.

        :return: Signature data as bytes.
        """
        return bytes(self._data)

    @data.setter
    def data(self, value: Union[bytes, bytearray]) -> None:
        """Set signature data.

        :param value: New signature data as bytes or bytearray.
        """
        self._data = bytearray(value)

    def export(self) -> bytes:
        """Export signature to binary form including header.

        The method updates the header length to match the current signature size
        and combines the header data with the signature data.

        :return: Exported signature data as bytes.
        """
        self._header.length = self.size
        raw_data = self._header.export()
        raw_data += self.data
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse signature from binary data.

        :param data: Binary data to parse
        :raises SPSDKError: Invalid data format or parsing error
        :return: New Signature instance
        """
        header = Header.parse(data, SegmentTag.SIG.tag)
        return cls(header.param, data[Header.SIZE : header.length])
