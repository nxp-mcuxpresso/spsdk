#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""File including helping functions."""
import functools

from spsdk.crypto.cmac import cmac
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class KeyDerivationMode(SpsdkEnum):
    """Modes for Key derivation."""

    KDK = (1, "KDK", "Key Derivation Key mode")
    BLK = (2, "BLK", "Block Key Derivation mode")


class KeyDerivator:
    """Engine for generating derived keys."""

    def __init__(self, pck: bytes, timestamp: int, key_length: int, kdk_access_rights: int) -> None:
        """Initialize the KeyDerivator.

        :param pck: Part Common Key, base user key for all key derivations
        :param timestamp: Timestamp used for creating the KeyDerivationKey
        :param key_length: Requested key length after derivation (128/256bits)
        :param kdk_access_rights: KeyDerivationKey access rights
        """
        self.pck = pck
        self.key_length = key_length
        self.kdk_access_rights = kdk_access_rights
        self.timestamp = timestamp
        self.kdk = self._derive_kdk()

    def _derive_kdk(self) -> bytes:
        """Derive the KeyDerivationKey from PCK and timestamp."""
        return derive_kdk(self.pck, self.timestamp, self.key_length, self.kdk_access_rights)

    def get_block_key(self, block_number: int) -> bytes:
        """Derive key for particular block."""
        return derive_block_key(self.kdk, block_number, self.key_length, self.kdk_access_rights)


def derive_block_key(
    kdk: bytes, block_number: int, key_length: int, kdk_access_rights: int
) -> bytes:
    """Derive encryption AES key for given block.

    :param kdk: Key Derivation Key
    :param block_number: Block number
    :param key_length: Required key length (128/256)
    :param kdk_access_rights: Key Derivation Key access rights (0-3)
    :return: AES key for given block
    """
    return _derive_key(
        key=kdk,
        derivation_constant=block_number,
        kdk_access_rights=kdk_access_rights,
        key_length=key_length,
        mode=KeyDerivationMode.BLK,
    )


def derive_kdk(pck: bytes, timestamp: int, key_length: int, kdk_access_rights: int) -> bytes:
    """Derive the Key Derivation Key.

    :param pck: Part Common Key
    :param timestamp: Timestamp for KDK derivation
    :param key_length: Requested key length (128/256b)
    :param kdk_access_rights: KDK access rights (0-3)
    :return: Key Derivation Key
    """
    return _derive_key(
        key=pck,
        derivation_constant=timestamp,
        kdk_access_rights=kdk_access_rights,
        key_length=key_length,
        mode=KeyDerivationMode.KDK,
    )


def _derive_key(
    key: bytes,
    derivation_constant: int,
    kdk_access_rights: int,
    mode: KeyDerivationMode,
    key_length: int,
) -> bytes:
    """Derive new AES key from the provided key.

    :param key: Base (original) key
    :param derivation_constant: Derivation constant for key derivation
    :param kdk_access_rights: Key Derivation Key access rights (0-3)
    :param mode: Mode of derivation (1/2; see `KeyDerivationMode`)
    :param key_length: Requested key length (128/256b)
    :return: New (derived) AES key
    """
    # use partial to save typing later on
    derivation_data = functools.partial(
        _get_key_derivation_data,
        derivation_constant=derivation_constant,
        kdk_access_rights=kdk_access_rights,
        mode=mode,
        key_length=key_length,
    )

    result = cmac(data=derivation_data(iteration=1), key=key)
    if key_length == 256:
        result += cmac(data=derivation_data(iteration=2), key=key)
    return result


def _get_key_derivation_data(
    derivation_constant: int,
    kdk_access_rights: int,
    mode: KeyDerivationMode,
    key_length: int,
    iteration: int,
) -> bytes:
    """Generate data for AES key derivation.

    :param derivation_constant: Number for the key derivation
    :param kdk_access_rights: KeyDerivationKey access rights (0-3)
    :param mode: Mode for key derivation (1/2, see: `KeyDerivationMode`)
    :param key_length: Requested key length (128/256b)
    :param iteration: Iteration of the key derivation
    :return: Data used for key derivation
    :raises SPSDKError: Invalid mode.
    :raises SPSDKError: Invalid kdk access rights.
    :raises SPSDKError: Invalid key length.
    """
    if mode not in KeyDerivationMode:
        raise SPSDKError("Invalid mode")
    if kdk_access_rights not in [0, 1, 2, 3]:
        raise SPSDKError("Invalid kdk access rights")
    if key_length not in [128, 256]:
        raise SPSDKError("Invalid key length")

    label = int.to_bytes(derivation_constant, length=12, byteorder=Endianness.LITTLE.value)
    context = bytes(8)
    context += int.to_bytes(kdk_access_rights << 6, length=1, byteorder=Endianness.BIG.value)
    context += b"\x01" if mode == KeyDerivationMode.KDK else b"\x10"
    context += bytes(1)
    key_option = 0x20 if key_length == 128 else 0x21
    context += int.to_bytes(key_option, length=1, byteorder=Endianness.BIG.value)
    length = int.to_bytes(key_length, length=4, byteorder=Endianness.BIG.value)
    i = int.to_bytes(iteration, length=4, byteorder=Endianness.BIG.value)
    result = label + context + length + i
    return result


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
