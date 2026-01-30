#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Common definitions and enumerations for HSE (Hardware Security Engine) key operations.

This module provides common types and enumerations used across HSE key management..
"""

from enum import IntEnum
from typing import Any

from typing_extensions import Self

from spsdk.exceptions import SPSDKParsingError
from spsdk.utils.config import Config
from spsdk.utils.spsdk_enum import SpsdkEnum


class HseKeyBits(IntEnum):
    """HSE Key Bits.

    Some default key bits values.
    """

    INVALID = 0xFFFF
    ZERO = 0
    KEY64_BITS = 64
    KEY128_BITS = 128
    KEY160_BITS = 160
    KEY192_BITS = 192
    KEY224_BITS = 224
    KEY240_BITS = 240
    KEY256_BITS = 256
    KEY320_BITS = 320
    KEY384_BITS = 384
    KEY512_BITS = 512
    KEY521_BITS = 521
    KEY638_BITS = 638
    KEY1024_BITS = 1024
    KEY2048_BITS = 2048
    KEY3072_BITS = 3072
    KEY4096_BITS = 4096


class KeyType(SpsdkEnum):
    """Enumeration of HSE key types.

    Defines the available key types that can be used with HSE key operations.
    """

    SHE = (0x11, "SHE", "SHE key")
    AES = (0x12, "AES", "AES key")
    HMAC = (0x20, "HMAC", "HMAC key")
    SHARED_SECRET = (0x30, "SHARED_SECRET", "Shared secret key")
    SIPHASH = (0x40, "SIPHASH", "SipHash key")
    ECC_PAIR = (0x87, "ECC_PAIR", "ECC key pair")
    ECC_PUB = (0x88, "ECC_PUB", "ECC public key")
    ECC_PUB_EXT = (0x89, "ECC_PUB_EXT", "ECC public key external")
    RSA_PAIR = (0x97, "RSA_PAIR", "RSA key pair")
    RSA_PUB = (0x98, "RSA_PUB", "RSA public key")
    RSA_PUB_EXT = (0x99, "RSA_PUB_EXT", "RSA public key external")
    DH_PAIR = (0xA7, "DH_PAIR", "Diffie-Hellman key pair")
    DH_PUB = (0xA8, "DH_PUB", "Diffie-Hellman public key")


class KeyCatalogId(SpsdkEnum):
    """HSE key catalog type.

    A key catalog is a memory container that holds groups of keys.
    The catalog defines the type of storage (volatile / non-volatile) and the visibility to the application (host).
    """

    ROM = (0, "ROM", "ROM key catalog (NXP keys)")
    NVM = (1, "NVM", "NVM key catalog")
    RAM = (2, "RAM", "RAM key catalog")


class KeyHandle:
    """HSE Key Handle.

    All keys used in cryptographic operations are referenced by a unique key handle.
    The key handle is a 32-bit integer: the key catalog(byte2), group index in catalog (byte1)
    and key slot index (byte0).
    """

    ROM_KEY_AES256_KEY0 = 0x00000000
    ROM_KEY_AES256_KEY1 = 0x00000001
    ROM_KEY_AES256_KEY2 = 0x00000002
    ROM_KEY_RSA3072_PUB_KEY0 = 0x00000100
    ROM_KEY_RSA2048_PUB_KEY1 = 0x00000101
    ROM_KEY_ECC256_PUB_KEY0 = 0x00000200

    INVALID_KEY_HANDLE = 0xFFFFFFFF
    INVALID_GROUP_IDX = 0xFF
    INVALID_SLOT_IDX = 0xFF

    def __init__(self, catalog_id: KeyCatalogId, group_idx: int, slot_idx: int) -> None:
        """Initialize a key handle from its components.

        :param catalog_id: Key catalog ID
        :param group_idx: Group index in catalog
        :param slot_idx: Key slot index within the group
        """
        self.catalog_id = catalog_id
        self.group_idx = group_idx
        self.slot_idx = slot_idx

    @classmethod
    def get_size(cls) -> int:
        """Get the size of the key handle structure.

        :return: Size in bytes
        """
        return 4

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse a key handle from bytes.

        :param data: Raw key handle value as bytes (4 bytes)
        :return: KeyHandle object
        :raises SPSDKParsingError: If data length is invalid
        """
        if len(data) < cls.get_size():
            raise SPSDKParsingError(
                f"Invalid key handle data length: {len(data)}, expected at least 4 bytes"
            )

        handle = int.from_bytes(data[: cls.get_size()], byteorder="little")
        return cls.from_handle(handle)

    @classmethod
    def from_handle(cls, handle: int) -> Self:
        """Create a KeyHandle object from a raw handle value.

        :param handle: Raw key handle as integer
        :return: KeyHandle object
        """
        catalog_id = (handle >> 16) & 0xFF
        group_idx = (handle >> 8) & 0xFF
        slot_idx = handle & 0xFF
        return cls(KeyCatalogId.from_tag(catalog_id), group_idx, slot_idx)

    def export(self) -> bytes:
        """Export the key handle to bytes.

        :return: Raw key handle as bytes (4 bytes)
        """
        return self.handle.to_bytes(self.get_size(), byteorder="little")

    @property
    def handle(self) -> int:
        """Get the raw key handle value.

        :return: Raw key handle as integer
        """
        return (self.catalog_id.tag << 16) | (self.group_idx << 8) | self.slot_idx

    def is_valid(self) -> bool:
        """Check if the key handle is valid.

        :return: True if valid, False otherwise
        """
        return (
            self.handle != self.INVALID_KEY_HANDLE
            and self.group_idx != self.INVALID_GROUP_IDX
            and self.slot_idx != self.INVALID_SLOT_IDX
        )

    @property
    def is_rom_key(self) -> bool:
        """Check if the key handle refers to a ROM key.

        :return: True if ROM key, False otherwise
        """
        return self.catalog_id == KeyCatalogId.ROM

    def __str__(self) -> str:
        """Format the key handle for display.

        :return: Formatted string representation
        """
        return f"Key Handle: 0x{self.handle:08X} (Catalog: {self.catalog_id.label}, Group: {self.group_idx}, Slot: {self.slot_idx})"

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load key handle from configuration.

        :param config: Configuration object containing SMR entry settings
        :return: SmrEntry instance
        :raises SPSDKValueError: If configuration is invalid
        """
        catalog_id = KeyCatalogId.from_label(config.get_str("catalogId"))
        group_idx = config.get_int("groupIdx")
        slot_idx = config.get_int("slotIdx")
        return cls(catalog_id, group_idx, slot_idx)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary from key handle.

        :return: Configuration dictionary that can be used to recreate this key handle
        """
        return {
            "catalogId": self.catalog_id.label,
            "groupIdx": self.group_idx,
            "slotIdx": self.slot_idx,
        }
