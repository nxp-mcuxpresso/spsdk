#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB3.1 key derivation and cryptographic helper functions.

This module provides key derivation functionality and utility functions
for SB3.1 secure boot files, including block key derivation and data
padding operations.
"""

import functools

from spsdk.crypto.cmac import cmac
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class KeyDerivationMode(SpsdkEnum):
    """Key derivation mode enumeration for SB3.1 file format.

    This enumeration defines the available modes for key derivation operations
    in SB3.1 secure boot files, including Key Derivation Key mode and Block
    Key Derivation mode.
    """

    KDK = (1, "KDK", "Key Derivation Key mode")
    BLK = (2, "BLK", "Block Key Derivation mode")


class KeyDerivator:
    """SPSDK Key Derivation Engine for SB3.1 format.

    This class manages cryptographic key derivation operations for Secure Binary 3.1 files,
    providing functionality to generate Key Derivation Keys (KDK) from Part Common Keys (PCK)
    and derive block-specific encryption keys for secure boot image processing.
    """

    def __init__(self, pck: bytes, timestamp: int, key_length: int, kdk_access_rights: int) -> None:
        """Initialize the KeyDerivator.

        Sets up key derivation functionality with the provided parameters and derives
        the initial KeyDerivationKey.

        :param pck: Part Common Key, base user key for all key derivations.
        :param timestamp: Timestamp used for creating the KeyDerivationKey.
        :param key_length: Requested key length after derivation (128/256 bits).
        :param kdk_access_rights: KeyDerivationKey access rights.
        """
        self.pck = pck
        self.key_length = key_length
        self.kdk_access_rights = kdk_access_rights
        self.timestamp = timestamp
        self.kdk = self._derive_kdk()

    def _derive_kdk(self) -> bytes:
        """Derive the KeyDerivationKey from PCK and timestamp.

        This method computes the Key Derivation Key (KDK) using the Part Common Key (PCK),
        timestamp, key length, and KDK access rights through the derive_kdk function.

        :return: The derived Key Derivation Key as bytes.
        """
        return derive_kdk(self.pck, self.timestamp, self.key_length, self.kdk_access_rights)

    def get_block_key(self, block_number: int) -> bytes:
        """Derive key for particular block.

        :param block_number: Block number for which to derive the key.
        :return: Derived key as bytes for the specified block.
        """
        return derive_block_key(self.kdk, block_number, self.key_length, self.kdk_access_rights)


def derive_block_key(
    kdk: bytes, block_number: int, key_length: int, kdk_access_rights: int
) -> bytes:
    """Derive encryption AES key for given block.

    This function uses the Key Derivation Key (KDK) to generate a block-specific
    AES encryption key using the specified parameters and block derivation mode.

    :param kdk: Key Derivation Key used as the base for key derivation.
    :param block_number: Block number used as derivation constant.
    :param key_length: Required key length in bits (128 or 256).
    :param kdk_access_rights: Key Derivation Key access rights value (0-3).
    :return: Derived AES key for the specified block.
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

    This function creates a KDK by deriving it from the Part Common Key using the provided
    timestamp and access rights parameters.

    :param pck: Part Common Key used as base for derivation.
    :param timestamp: Timestamp value used in KDK derivation process.
    :param key_length: Requested key length in bits (128 or 256).
    :param kdk_access_rights: KDK access rights level (valid range 0-3).
    :return: Derived Key Derivation Key as bytes.
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

    Uses CMAC-based key derivation with specified parameters. For 256-bit keys,
    performs two iterations of CMAC operations.

    :param key: Base (original) key used for derivation.
    :param derivation_constant: Derivation constant for key derivation algorithm.
    :param kdk_access_rights: Key Derivation Key access rights (0-3).
    :param mode: Mode of derivation (1/2; see `KeyDerivationMode`).
    :param key_length: Requested key length in bits (128/256).
    :return: New (derived) AES key as bytes.
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

    This function creates the data structure required for AES key derivation by combining
    label, context, length, and iteration parameters according to the key derivation specification.

    :param derivation_constant: Number for the key derivation (12 bytes when converted).
    :param kdk_access_rights: KeyDerivationKey access rights, must be 0-3.
    :param mode: Mode for key derivation, see KeyDerivationMode enum.
    :param key_length: Requested key length in bits, must be 128 or 256.
    :param iteration: Iteration number of the key derivation process.
    :return: Formatted data bytes used for key derivation.
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
    """Add leading zeros to byte data to reach specified size.

    :param byte_data: Input data as bytes array.
    :param return_size: Target size of the output data in bytes.
    :return: Byte data padded with leading zeros to reach the specified size.
    """
    padding_size = return_size - len(byte_data)
    byte_data_with_padding = bytes("\x00" * padding_size, "utf8") + byte_data
    return byte_data_with_padding


def add_trailing_zeros(byte_data: bytes, return_size: int) -> bytes:
    """Pad byte data with trailing zeros to reach specified size.

    :param byte_data: Input data as bytes array to be padded.
    :param return_size: Target size of the output data in bytes.
    :return: Padded byte data with trailing zeros.
    """
    size_of_zeros = return_size - len(byte_data)
    byte_data_with_padding = byte_data + bytes("\x00" * size_of_zeros, "utf8")
    return byte_data_with_padding
