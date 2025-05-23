#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for handling Message Authentication Code (MAC) used in High Assurance Boot (HAB).

This module provides functionality for working with MAC structures in HAB, which are used
for authenticated encryption and decryption operations.
"""
from struct import pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.utils.abstract import BaseClass


class MAC(BaseClass):
    """Structure that holds initial parameter for AES encryption/decryption.

    - nonce - initialization vector for AEAD AES128 decryption
    - mac - message authentication code to verify the decryption was successful
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
        """Constructor.

        :param version: format version, should be 0x4x
        :param nonce_len: number of NONCE bytes
        :param mac_len: number of MAC bytes
        :param data: nonce and mac bytes joined together
        """
        self._header = Header(tag=SegmentTag.MAC.tag, param=version)
        self.nonce_len = nonce_len
        self.mac_len = mac_len
        self._data: bytes = bytes() if data is None else bytes(data)
        if data:
            self._validate_data()

    @property
    def size(self) -> int:
        """Size of binary representation in bytes."""
        return Header.SIZE + 4 + self.nonce_len + self.mac_len

    def _validate_data(self) -> None:
        """Validates the data.

        :raises SPSDKError: If data length does not match with parameters
        """
        if len(self.data) != self.nonce_len + self.mac_len:
            raise SPSDKError(
                f"length of data ({len(self.data)}) does not match with "
                f"nonce_bytes({self.nonce_len})+mac_bytes({self.mac_len})"
            )

    @property
    def data(self) -> bytes:
        """NONCE and MAC bytes joined together."""
        return self._data

    @data.setter
    def data(self, value: bytes) -> None:
        """Setter.

        :param value: NONCE and MAC bytes joined together
        """
        self._data = value
        self._validate_data()

    @property
    def nonce(self) -> bytes:
        """NONCE bytes for the encryption/decryption."""
        self._validate_data()
        return self._data[0 : self.nonce_len]

    @property
    def mac(self) -> bytes:
        """MAC bytes for the encryption/decryption."""
        self._validate_data()
        return self._data[self.nonce_len : self.nonce_len + self.mac_len]

    def update_aead_encryption_params(self, nonce: bytes, mac: bytes) -> None:
        """Update AEAD encryption parameters for encrypted image.

        :param nonce: initialization vector, length depends on image size,
        :param mac: message authentication code used to authenticate decrypted data, 16 bytes
        :raises SPSDKError: If incorrect length of mac
        :raises SPSDKError: If incorrect length of nonce
        :raises SPSDKError: If incorrect number of MAC bytes"
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
        return len(self._data)

    def __repr__(self) -> str:
        return (
            f"MAC <Ver: {self._header.version_major:X}.{self._header.version_minor:X}, "
            f"Nonce: {self.nonce_len}, MAC: {self.mac_len}>"
        )

    def __str__(self) -> str:
        """Text info about the instance."""
        msg = "-" * 60 + "\n"
        msg += f"MAC (Version: {self._header.version_major >> 4:X}.{self._header.version_minor & 0xF:X})\n"
        msg += "-" * 60 + "\n"
        msg += f"Nonce Len: {self.nonce_len} Bytes\n"
        msg += f"MAC Len:   {self.mac_len} Bytes\n"
        msg += f"[{self._data.hex()}]\n"
        return msg

    def export(self) -> bytes:
        """Export instance into binary form (serialization).

        :return: binary form
        """
        self._validate_data()
        self._header.length = self.size
        raw_data = self._header.export()
        raw_data += pack(">4B", 0, self.nonce_len, 0, self.mac_len)
        raw_data += self.data
        return raw_data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data and creates the instance (deserialization).

        :param data: being parsed
        :return: the instance
        """
        header = Header.parse(data, SegmentTag.MAC.tag)
        (_, nonce_bytes, _, mac_bytes) = unpack_from(">4B", data, Header.SIZE)
        return cls(
            header.param,
            nonce_bytes,
            mac_bytes,
            data[Header.SIZE + 4 : header.length],
        )
