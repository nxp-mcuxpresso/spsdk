#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB Message Authentication Code utilities.

This module provides functionality for handling MAC structures used in High Assurance Boot (HAB)
for authenticated encryption and decryption operations.
"""

from struct import pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.utils.abstract import BaseClass


class MAC(BaseClass):
    """HAB MAC structure for AES encryption/decryption parameters.

    This class represents a MAC (Message Authentication Code) structure used in HAB
    (High Assurance Boot) operations. It manages the nonce (initialization vector)
    and MAC data required for AEAD AES128 encryption/decryption operations, providing
    validation and binary representation capabilities.

    :cvar AES128_BLK_LEN: AES block size in bytes, also matches MAC size (16 bytes).
    """

    # AES block size in bytes; This also match size of the MAC and
    AES128_BLK_LEN = 16

    def __init__(
        self,
        version: int = 0x40,
        nonce_len: int = 0,
        mac_len: int = AES128_BLK_LEN,
        data: Optional[bytes] = None,
    ):
        """Initialize HAB MAC segment.

        Creates a new MAC (Message Authentication Code) segment for HAB (High Assurance Boot)
        with specified version, nonce length, MAC length, and optional data.

        :param version: Format version, should be 0x4x (default: 0x40).
        :param nonce_len: Number of NONCE bytes (default: 0).
        :param mac_len: Number of MAC bytes (default: AES128_BLK_LEN).
        :param data: Nonce and MAC bytes joined together (default: None).
        """
        self._header = Header(tag=SegmentTag.MAC.tag, param=version)
        self.nonce_len = nonce_len
        self.mac_len = mac_len
        self._data: bytes = bytes() if data is None else bytes(data)
        if data:
            self._validate_data()

    @property
    def size(self) -> int:
        """Get the size of binary representation in bytes.

        Calculates the total size including header, length field, nonce, and MAC components.

        :return: Size in bytes of the complete binary representation.
        """
        return Header.SIZE + 4 + self.nonce_len + self.mac_len

    def _validate_data(self) -> None:
        """Validate the MAC data structure integrity.

        Ensures that the total data length matches the expected combination of nonce length
        and MAC length parameters.

        :raises SPSDKError: If data length does not match with parameters.
        """
        if len(self.data) != self.nonce_len + self.mac_len:
            raise SPSDKError(
                f"length of data ({len(self.data)}) does not match with "
                f"nonce_bytes({self.nonce_len})+mac_bytes({self.mac_len})"
            )

    @property
    def data(self) -> bytes:
        """Get NONCE and MAC bytes joined together.

        :return: Combined NONCE and MAC data as bytes.
        """
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Set MAC data containing NONCE and MAC bytes.

        :param value: NONCE and MAC bytes joined together
        :raises SPSDKValueError: Invalid data format or length during validation
        """
        self._data = value
        self._validate_data()

    @property
    def nonce(self) -> bytes:
        """Get NONCE bytes for the encryption/decryption.

        :raises SPSDKError: If the data validation fails.
        :return: NONCE bytes of specified length.
        """
        self._validate_data()
        return self._data[0 : self.nonce_len]

    @property
    def mac(self) -> bytes:
        """Get MAC bytes for the encryption/decryption.

        The method extracts the Message Authentication Code from the internal data
        buffer based on the configured nonce and MAC lengths.

        :raises SPSDKError: If the internal data validation fails.
        :return: MAC bytes as a byte array.
        """
        self._validate_data()
        return self._data[self.nonce_len : self.nonce_len + self.mac_len]

    def update_aead_encryption_params(self, nonce: bytes, mac: bytes) -> None:
        """Update AEAD encryption parameters for encrypted image.

        This method sets the nonce and MAC values for AEAD encryption, validating their lengths
        according to the encryption requirements.

        :param nonce: Initialization vector with length between 11-13 bytes depending on image size
        :param mac: Message authentication code used to authenticate decrypted data, must be 16 bytes
        :raises SPSDKError: If incorrect length of mac
        :raises SPSDKError: If incorrect length of nonce
        :raises SPSDKError: If incorrect number of MAC bytes
        """
        if len(mac) != MAC.AES128_BLK_LEN:
            raise SPSDKError("Incorrect length of mac")
        if len(nonce) < 11 or len(nonce) > 13:
            raise SPSDKError("Incorrect length of nonce")
        self.nonce_len = len(nonce)
        if self.mac_len != MAC.AES128_BLK_LEN:
            raise SPSDKError("Incorrect number of MAC bytes")
        self.data = nonce + mac

    def __len__(self) -> int:
        """Get the length of the MAC data.

        :return: Number of bytes in the MAC data.
        """
        return len(self._data)

    def __repr__(self) -> str:
        """Return string representation of MAC object.

        Provides a formatted string containing version information, nonce length,
        and MAC length for debugging and logging purposes.

        :return: Formatted string with MAC object details.
        """
        return (
            f"MAC <Ver: {self._header.version_major:X}.{self._header.version_minor:X}, "
            f"Nonce: {self.nonce_len}, MAC: {self.mac_len}>"
        )

    def __str__(self) -> str:
        """Get text representation of the MAC instance.

        Provides formatted information about the MAC including version, nonce length,
        MAC length, and hexadecimal data representation.

        :return: Formatted string with MAC instance details.
        """
        msg = "-" * 60 + "\n"
        msg += f"MAC (Version: {self._header.version_major >> 4:X}.{self._header.version_minor & 0xF:X})\n"
        msg += "-" * 60 + "\n"
        msg += f"Nonce Len: {self.nonce_len} Bytes\n"
        msg += f"MAC Len:   {self.mac_len} Bytes\n"
        msg += f"[{self._data.hex()}]\n"
        return msg

    def export(self) -> bytes:
        """Export instance into binary form (serialization).

        The method validates internal data, updates header length to match instance size,
        and serializes all components including header, nonce length, MAC length, and data
        into a binary format.

        :raises SPSDKError: If data validation fails.
        :return: Serialized binary representation of the instance.
        """
        self._validate_data()
        self._header.length = self.size
        raw_data = self._header.export()
        raw_data += pack(">4B", 0, self.nonce_len, 0, self.mac_len)
        raw_data += self.data
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data and create HAB MAC instance.

        Deserializes binary data into a HAB MAC object by parsing the header and extracting
        nonce bytes, MAC bytes, and payload data.

        :param data: Binary data to be parsed into HAB MAC instance.
        :return: New HAB MAC instance created from the parsed data.
        """
        header = Header.parse(data, SegmentTag.MAC.tag)
        (_, nonce_bytes, _, mac_bytes) = unpack_from(">4B", data, Header.SIZE)
        return cls(
            header.param,
            nonce_bytes,
            mac_bytes,
            data[Header.SIZE + 4 : header.length],
        )
