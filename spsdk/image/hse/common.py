#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Common definitions and enumerations for HSE (Hardware Security Engine) key operations.

This module provides common types and enumerations used across HSE key management..
"""

import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from struct import calcsize, pack, unpack
from typing import Any, Optional, Type

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKParsingError, SPSDKValueError
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import LITTLE_ENDIAN, UINT8, UINT16, UINT32, Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class HseKeyBits(IntEnum):
    """HSE Key Bits.

    Some default key bits values.
    """

    INVALID = 0xFFFF
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


class HashAlgo(SpsdkEnum):
    """Enumeration of HSE hash algorithms."""

    NULL = (0, "NULL", "None")
    RESERVED1 = (1, "RESERVED1", "Reserved (MD5 obsolete)")
    SHA1 = (2, "SHA1", "SHA1 hash")
    SHA224 = (3, "SHA224", "SHA224 hash")
    SHA256 = (4, "SHA256", "SHA256 hash")
    SHA384 = (5, "SHA384", "SHA384 hash")
    SHA512 = (6, "SHA512", "SHA512 hash")
    SHA512_224 = (7, "SHA512_224", "SHA512_224 hash")
    SHA512_256 = (8, "SHA512_256", "SHA512_256 hash")
    SHA3_224 = (9, "SHA3_224", "SHA3_224 hash")
    SHA3_256 = (10, "SHA3_256", "SHA3_256 hash")
    SHA3_384 = (11, "SHA3_384", "SHA3_384 hash")
    SHA3_512 = (12, "SHA3_512", "SHA3_512 hash")
    MP = (13, "MP", "Miyaguchi-Preneel compression using AES-ECB with 128-bit key size")


class AuthSchemeEnum(SpsdkEnum):
    """Enumeration of HSE signature schemes."""

    CMAC = (0x11, "CMAC", "CMAC (AES)")
    GMAC = (0x12, "GMAC", "GMAC (AES)")
    XCBC_MAC = (0x13, "XCBC_MAC", "XCBC MAC (AES128)")
    HMAC = (0x20, "HMAC", "HMAC")
    ECDSA = (0x80, "ECDSA", "ECDSA signature scheme")
    EDDSA = (0x81, "EDDSA", "EdDSA signature scheme")
    RSASSA_PKCS1_V15 = (0x93, "RSASSA_PKCS1_V15", "RSASSA_PKCS1_V15 signature scheme")
    RSASSA_PSS = (0x94, "RSASSA_PSS", "RSASSA_PSS signature scheme")

    def validate(self, family: FamilyRevision) -> None:
        """Validate that the auth scheme is available for the given family.

        :param family: Target device family and revision
        :raises SPSDKError: If auth scheme is not available for the family
        """
        schemes = self.get_available_schemes(family)
        if self not in schemes:
            raise SPSDKError(
                f"Authentication scheme {self.label} is not available for family {family.name}"
            )

    @classmethod
    def get_available_schemes(cls, family: FamilyRevision) -> list[Self]:
        """Get available authentication schemes for the given family."""
        db = get_db(family)
        available_schemes = db.get_list(DatabaseManager.HSE, "auth_schemes")
        return [cls.from_label(label) for label in available_schemes]


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

    def __init__(self, handle: int) -> None:
        """Initialize a key handle from its components.

        :param catalog_id: Key catalog ID
        :param group_idx: Group index in catalog
        :param slot_idx: Key slot index within the group
        """
        self._handle = handle

    def __str__(self) -> str:
        """Format the key handle for display.

        :return: Formatted string representation
        """
        return f"Key Handle: 0x00010304(Key Catalog: {self.catalog_id.label}, Group: {self.group_idx}, Slot: {self.slot_idx})"

    def __repr__(self) -> str:
        """Return representation of key handle for debugging.

        :return: String representation showing the raw handle value and its components
        """
        return (
            f"KeyHandle(handle=0x{self.handle:08X}, "
            f"catalog={self.catalog_id.label}, "
            f"group={self.group_idx}, "
            f"slot={self.slot_idx})"
        )

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
        handle = int.from_bytes(data[: cls.get_size()], byteorder=Endianness.LITTLE.value)
        return cls(handle)

    @property
    def group_idx(self) -> int:
        """Group index."""
        return (self.handle >> 8) & 0xFF

    @property
    def slot_idx(self) -> int:
        """Slot index."""
        return self.handle & 0xFF

    @property
    def catalog_id(self) -> KeyCatalogId:
        """Catalog id."""
        catalog_id = (self.handle >> 16) & 0xFF
        try:
            return KeyCatalogId.from_tag(catalog_id)
        except SPSDKKeyError:
            raise SPSDKError("Invalid catalog with id: 0x{:02X}".format(catalog_id))

    def export(self) -> bytes:
        """Export the key handle to bytes.

        :return: Raw key handle as bytes (4 bytes)
        """
        return self.handle.to_bytes(self.get_size(), byteorder=Endianness.LITTLE.value)

    @property
    def handle(self) -> int:
        """Get the raw key handle value.

        :return: Raw key handle as integer
        """
        return self._handle

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
        return cls.from_attributes(catalog_id, group_idx, slot_idx)

    @classmethod
    def from_attributes(cls, catalog_id: KeyCatalogId, group_idx: int, slot_idx: int) -> Self:
        """Create the object from attributes."""
        return cls((catalog_id.tag << 16) | (group_idx << 8) | (slot_idx))

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary from key handle.

        :return: Configuration dictionary that can be used to recreate this key handle
        """
        return {
            "catalogId": self.catalog_id.label,
            "groupIdx": self.group_idx,
            "slotIdx": self.slot_idx,
        }


class CipherAlgo(SpsdkEnum):
    """Enumeration of HSE cipher algorithms."""

    NULL = (0x00, "NULL", "NULL cipher")
    AES = (0x10, "AES", "AES cipher")


class AuthScheme:
    """HSE authentication scheme.

    This class represents the authentication scheme used to verify data integrity
    and authenticity. It can be either a MAC-based scheme or a signature-based scheme.
    """

    AUTH_SCH: AuthSchemeEnum  # Will be overridden by subclasses
    HEADER_FORMAT: str = "<BBBB"
    SCH_FORMAT: str

    _registry: dict[AuthSchemeEnum, Type["AuthScheme"]] = {}

    def __repr__(self) -> str:
        """Return representation of authentication scheme.

        :return: String representation for debugging
        """
        return f"{self.__class__.__name__}({self.AUTH_SCH.label})"

    @classmethod
    def get_scheme_data_size(cls) -> int:
        """Get the size of the auth scheme structure.

        :return: Size in bytes
        """
        return struct.calcsize(cls.SCH_FORMAT)

    @classmethod
    def get_size(cls) -> int:
        """Get the size of the auth scheme structure including header and scheme data.

        :return: Size in bytes
        """
        return struct.calcsize(cls.HEADER_FORMAT) + cls.get_scheme_data_size()

    @property
    def size(self) -> int:
        """Get the size of the auth scheme structure.

        :return: Size in bytes
        """
        return self.get_size()

    @classmethod
    def register(cls, scheme_cls: Type["AuthScheme"]) -> Type["AuthScheme"]:
        """Register a MAC scheme implementation.

        :param mac_scheme_cls: The MAC scheme class to register
        :return: The registered class (for decorator usage)
        """
        if not hasattr(scheme_cls, "AUTH_SCH") or scheme_cls.AUTH_SCH is None:
            raise SPSDKValueError(f"Auth scheme class {scheme_cls.__name__} must define AUTH_SCH")
        cls._registry[scheme_cls.AUTH_SCH] = scheme_cls
        return scheme_cls

    @classmethod
    def auth_schemes(cls) -> dict[AuthSchemeEnum, Type["AuthScheme"]]:
        """Get the registry of all registered authentication schemes."""
        return cls._registry

    @classmethod
    def create(cls, auth_scheme: AuthSchemeEnum, **kwargs: Any) -> "AuthScheme":
        """Create an authentication scheme using a MAC algorithm.

        :param auth_scheme: The MAC algorithm to use
        :param kwargs: Additional parameters for the specific MAC scheme
        :return: HseAuthScheme instance with MAC scheme
        """
        if auth_scheme not in cls._registry:
            raise SPSDKValueError(f"Unsupported authentication scheme: {auth_scheme}")
        return cls._registry[auth_scheme](**kwargs)

    @property
    def is_mac_scheme(self) -> bool:
        """Check if this is a MAC-based authentication scheme.

        :return: True if MAC-based, False if signature-based
        """
        return isinstance(self, MacScheme)

    @property
    def is_signature_scheme(self) -> bool:
        """Check if this is a signature-based authentication scheme.

        :return: True if signature-based, False if MAC-based
        """
        return isinstance(self, SignScheme)

    def export(self) -> bytes:
        """Export the signature scheme to binary format.

        :return: Binary representation of the signature scheme
        """
        # First pack the scheme type and reserved bytes
        result = struct.pack(self.HEADER_FORMAT, self.AUTH_SCH.tag, 0, 0, 0)

        # Then pack the scheme-specific data
        result += self._export_scheme()

        return result

    @abstractmethod
    def _export_scheme(self) -> bytes:
        """Export the scheme-specific data.

        :return: Binary representation of the scheme-specific data
        """

    @abstractmethod
    def __str__(self) -> str:
        """Return string representation of authentication scheme.

        :return: Human-readable string representation
        """

    @classmethod
    @abstractmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""

    @abstractmethod
    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary from auth scheme object.

        :return: Configuration dictionary that can be used to recreate this auth scheme
        """

    @classmethod
    def parse(cls, data: bytes) -> "AuthScheme":
        """Parse authentication scheme from binary data.

        :param data: Binary data containing scheme-specific parameters
        :return: AuthScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < struct.calcsize(cls.HEADER_FORMAT):
            raise SPSDKParsingError("Insufficient data for authentication scheme header")

        scheme_type_tag = data[0]

        try:
            scheme_type = AuthSchemeEnum.from_tag(scheme_type_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid authentication scheme type: 0x{scheme_type_tag:02X}")

        if scheme_type not in cls._registry:
            raise SPSDKParsingError(f"Unsupported authentication scheme: {scheme_type}")
        scheme_class = cls._registry[scheme_type]
        return scheme_class._parse_scheme(data[4:])  # Skip header (4 bytes)

    @classmethod
    @abstractmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse authentication scheme from binary data.

        :param data: Binary data containing scheme-specific parameters
        :return: AuthScheme instance
        """


class SignScheme(AuthScheme):
    """Base class for HSE signature schemes."""


class MacScheme(AuthScheme):
    """Base class for HSE MAC schemes."""


@dataclass
@AuthScheme.register
class EcdsaSignScheme(SignScheme):
    """ECDSA signature scheme parameters."""

    hash_algo: HashAlgo

    AUTH_SCH = AuthSchemeEnum.ECDSA
    SCH_FORMAT = "<BBBB"

    def __post_init__(self) -> None:
        """Validate parameters."""
        if self.hash_algo == HashAlgo.NULL:
            raise SPSDKValueError("Hash algorithm cannot be NULL for ECDSA")

    def _export_scheme(self) -> bytes:
        return struct.pack(self.SCH_FORMAT, self.hash_algo.tag, 0, 0, 0)

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse authentication scheme from binary data.

        :param data: Binary data containing scheme-specific parameters
        :return: AuthScheme instance
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for ECDSA scheme")

        hash_algo_tag = data[0]
        try:
            hash_algo = HashAlgo.from_tag(hash_algo_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid hash algorithm: 0x{hash_algo_tag:02X}")

        return cls(hash_algo=hash_algo)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {"ecdsa": {"hashAlgo": self.hash_algo.label}}

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        hash_algo = HashAlgo.from_label(config.get_str("hashAlgo"))
        return cls(hash_algo=hash_algo)

    def __str__(self) -> str:
        """Return string representation."""
        return f"ECDSA Signature Scheme (Hash: {self.hash_algo.label})"


@dataclass
@AuthScheme.register
class EddsaSignScheme(SignScheme):
    """EDDSA signature scheme parameters."""

    pre_hash_eddsa: bool = False
    context_length: int = 0
    context_addr: int = 0

    AUTH_SCH = AuthSchemeEnum.EDDSA
    SCH_FORMAT = "<BBBBL"

    def __post_init__(self) -> None:
        """Validate parameters."""
        if not isinstance(self.context_length, int) or not (0 <= self.context_length <= 255):
            raise SPSDKValueError("context_length must be between 0 and 255")
        if self.context_length > 0 and self.context_addr == 0:
            raise SPSDKValueError("p_context must be provided when context_length is non-zero")

    def _export_scheme(self) -> bytes:
        return struct.pack(
            self.SCH_FORMAT,
            int(self.pre_hash_eddsa),
            self.context_length,
            0,
            0,
            self.context_addr,
        )

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse EdDSA scheme from binary data.

        :param data: Binary data containing EdDSA parameters
        :return: EddsaSignScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for EdDSA scheme")

        pre_hash_eddsa = bool(data[0])
        context_length = data[1]
        context_addr = struct.unpack(LITTLE_ENDIAN + UINT32, data[4:8])[0]

        return cls(
            pre_hash_eddsa=pre_hash_eddsa, context_length=context_length, context_addr=context_addr
        )

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        config: dict[str, Any] = {
            "preHashEddsa": self.pre_hash_eddsa,
            "contextLength": self.context_length,
        }
        if self.context_length > 0:
            config["contextAddr"] = f"0x{self.context_addr:08X}"
        return {"eddsa": config}

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        pre_hash_eddsa = config.get_bool("preHashEddsa", default=False)
        context_length = config.get_int("contextLength", default=0)
        context_addr = config.get_int("contextAddr", default=0)
        return cls(
            pre_hash_eddsa=pre_hash_eddsa, context_length=context_length, context_addr=context_addr
        )

    def __str__(self) -> str:
        """Return string representation."""
        details = f"Pre-hash: {self.pre_hash_eddsa}"
        if self.context_length > 0:
            details += f", Context: {self.context_length} bytes @ 0x{self.context_addr:08X}"
        return f"EdDSA Signature Scheme ({details})"


@dataclass
@AuthScheme.register
class RsaPssSignScheme(SignScheme):
    """RSASSA_PSS signature scheme parameters."""

    hash_algo: HashAlgo
    salt_length: int = 0

    AUTH_SCH = AuthSchemeEnum.RSASSA_PSS
    SCH_FORMAT = "<BBBBL"

    def __post_init__(self) -> None:
        """Validate parameters."""
        if self.hash_algo == HashAlgo.NULL:
            raise SPSDKValueError("Hash algorithm cannot be NULL for RSA PSS")
        if not isinstance(self.salt_length, int) or self.salt_length < 0:
            raise SPSDKValueError("salt_length must be a non-negative integer")

    def _export_scheme(self) -> bytes:
        return struct.pack(
            self.SCH_FORMAT,
            self.hash_algo.tag,
            0,
            0,
            0,
            self.salt_length,
        )

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse RSASSA-PSS scheme from binary data.

        :param data: Binary data containing RSASSA-PSS parameters
        :return: RsaPssSignScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for RSASSA-PSS scheme")

        hash_algo_tag = data[0]
        try:
            hash_algo = HashAlgo.from_tag(hash_algo_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid hash algorithm: 0x{hash_algo_tag:02X}")

        salt_length = struct.unpack(LITTLE_ENDIAN + UINT32, data[4:8])[0]

        return cls(hash_algo=hash_algo, salt_length=salt_length)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {
            "rsassa_pss": {
                "hashAlgo": self.hash_algo.label,
                "saltLength": self.salt_length,
            }
        }

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        hash_algo = HashAlgo.from_label(config.get_str("hashAlgo"))
        salt_length = config.get_int("saltLength", default=0)
        return cls(hash_algo=hash_algo, salt_length=salt_length)

    def __str__(self) -> str:
        """Return string representation."""
        return (
            f"RSASSA-PSS Signature Scheme (Hash: {self.hash_algo.label}, Salt: {self.salt_length})"
        )


@dataclass
@AuthScheme.register
class RsaPkcs1v15Scheme(SignScheme):
    """RSASSA_PKCS1_V15 signature scheme parameters."""

    hash_algo: HashAlgo
    AUTH_SCH = AuthSchemeEnum.RSASSA_PKCS1_V15
    SCH_FORMAT = "<BBBB"

    def __post_init__(self) -> None:
        """Validate parameters."""
        if self.hash_algo == HashAlgo.NULL:
            raise SPSDKValueError("Hash algorithm cannot be NULL for RSA PKCS1v15")

    def _export_scheme(self) -> bytes:
        return struct.pack(self.SCH_FORMAT, self.hash_algo.tag, 0, 0, 0)

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse RSASSA-PKCS1-v1.5 scheme from binary data.

        :param data: Binary data containing RSASSA-PKCS1-v1.5 parameters
        :return: RsaPkcs1v15Scheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for RSASSA-PKCS1-v1.5 scheme")

        hash_algo_tag = data[0]
        try:
            hash_algo = HashAlgo.from_tag(hash_algo_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid hash algorithm: 0x{hash_algo_tag:02X}")

        return cls(hash_algo=hash_algo)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {"rsassa_pkcs1_v15": {"hashAlgo": self.hash_algo.label}}

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        hash_algo = HashAlgo.from_label(config.get_str("hashAlgo"))
        return cls(hash_algo=hash_algo)

    def __str__(self) -> str:
        """Return string representation."""
        return f"RSASSA-PKCS1-v1.5 Signature Scheme (Hash: {self.hash_algo.label})"


@dataclass
@AuthScheme.register
class CmacScheme(MacScheme):
    """CMAC scheme parameters."""

    cipher_algo: CipherAlgo = CipherAlgo.AES

    AUTH_SCH = AuthSchemeEnum.CMAC
    SCH_FORMAT = "<BBBB"

    def __post_init__(self) -> None:
        """Validate parameters."""
        if self.cipher_algo != CipherAlgo.AES:
            raise SPSDKValueError("Only AES cipher algorithm is supported for CMAC")

    def _export_scheme(self) -> bytes:
        return struct.pack(self.SCH_FORMAT, self.cipher_algo.tag, 0, 0, 0)

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse CMAC scheme from binary data.

        :param data: Binary data containing CMAC parameters
        :return: CmacScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for CMAC scheme")

        cipher_algo_tag = data[0]
        try:
            cipher_algo = CipherAlgo.from_tag(cipher_algo_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid cipher algorithm: 0x{cipher_algo_tag:02X}")

        return cls(cipher_algo=cipher_algo)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {"cmac": {"cipherAlgo": self.cipher_algo.label}}

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        cipher_algo = CipherAlgo.from_label(config.get_str("cipherAlgo", default="AES"))
        return cls(cipher_algo=cipher_algo)

    def __str__(self) -> str:
        """Return string representation."""
        return f"CMAC Scheme (Cipher: {self.cipher_algo.label})"


@dataclass
@AuthScheme.register
class HmacScheme(MacScheme):
    """HMAC scheme parameters."""

    hash_algo: HashAlgo

    AUTH_SCH = AuthSchemeEnum.HMAC
    SCH_FORMAT = "<BBBB"

    def _export_scheme(self) -> bytes:
        return struct.pack(self.SCH_FORMAT, self.hash_algo.tag, 0, 0, 0)

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse HMAC scheme from binary data.

        :param data: Binary data containing HMAC parameters
        :return: HmacScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for HMAC scheme")

        hash_algo_tag = data[0]
        try:
            hash_algo = HashAlgo.from_tag(hash_algo_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid hash algorithm: 0x{hash_algo_tag:02X}")

        return cls(hash_algo=hash_algo)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {"hmac": {"hashAlgo": self.hash_algo.label}}

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        return cls(hash_algo=HashAlgo.from_label(config.get_str("hashAlgo")))

    def __str__(self) -> str:
        """Return string representation."""
        return f"HMAC Scheme (Hash: {self.hash_algo.label})"


@dataclass
@AuthScheme.register
class GmacScheme(MacScheme):
    """GMAC scheme parameters."""

    iv_length: int
    iv_addr: int

    AUTH_SCH = AuthSchemeEnum.GMAC
    SCH_FORMAT = "<LL"

    def __post_init__(self) -> None:
        """Validate parameters."""
        if not isinstance(self.iv_length, int) or self.iv_length <= 0:
            raise SPSDKValueError("iv_length must be a positive integer")
        if not isinstance(self.iv_addr, int) or self.iv_addr == 0:
            raise SPSDKValueError("iv_addr must be a non-zero address")

    def _export_scheme(self) -> bytes:
        return struct.pack(
            self.SCH_FORMAT,
            self.iv_length,
            self.iv_addr,
        )

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse GMAC scheme from binary data.

        :param data: Binary data containing GMAC parameters
        :return: GmacScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for GMAC scheme")

        iv_length, iv_addr = struct.unpack(LITTLE_ENDIAN + UINT32 + UINT32, data[0:8])

        return cls(iv_length=iv_length, iv_addr=iv_addr)

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {
            "gmac": {
                "ivLength": self.iv_length,
                "ivAddr": f"0x{self.iv_addr:08X}",
            }
        }

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        iv_length = config.get_int("ivLength")
        iv_addr = config.get_int("ivAddr")
        return cls(iv_length=iv_length, iv_addr=iv_addr)

    def __str__(self) -> str:
        """Return string representation."""
        return f"GMAC Scheme (IV: {self.iv_length} bytes @ 0x{self.iv_addr:08X})"


@dataclass
@AuthScheme.register
class XcbcMacScheme(MacScheme):
    """XCBC-MAC scheme parameters."""

    AUTH_SCH = AuthSchemeEnum.XCBC_MAC
    SCH_FORMAT = "<BBBB"

    def _export_scheme(self) -> bytes:
        return struct.pack(self.SCH_FORMAT, 0, 0, 0, 0)

    @classmethod
    def _parse_scheme(cls, data: bytes) -> Self:
        """Parse XCBC-MAC scheme from binary data.

        :param data: Binary data containing XCBC-MAC parameters
        :return: XcbcMacScheme instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_scheme_data_size():
            raise SPSDKParsingError("Insufficient data for XCBC-MAC scheme")
        return cls()

    def get_config(self) -> dict[str, Any]:
        """Get configuration dictionary."""
        return {"xcbc_mac": {}}

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration from config object."""
        return cls()

    def __str__(self) -> str:
        """Return string representation."""
        return "XCBC-MAC Scheme (AES-128)"


class HseCipherSchemeBase(ABC):
    """HSE Cipher Scheme structure.

    This class represents a cipher scheme configuration for HSE (Hardware Security Engine)
    operations, encapsulating algorithm type, mode, and additional cipher options for
    cryptographic operations.
    """

    FORMAT: str

    def get_size(self) -> int:
        """Get the size of the cipher scheme in bytes."""
        return calcsize(self.FORMAT)

    @abstractmethod
    def export(self) -> bytes:
        """Convert cipher scheme to bytes."""
        pass

    @classmethod
    @abstractmethod
    def parse(self, data: bytes) -> Self:
        """Load cipher scheme from bytes."""
        pass


class HseAeadScheme(HseCipherSchemeBase):
    """AEAD cipher scheme parameters (default)."""

    FORMAT = LITTLE_ENDIAN + UINT8 + UINT8 + UINT16 + UINT32 + UINT32 + UINT32 + UINT32 + UINT32

    def __init__(
        self,
        auth_cipher_mode: int = 0,
        tag_length: int = 0,
        tag_addr: int = 0,
        iv_length: int = 0,
        iv_addr: int = 0,
        aad_length: int = 0,
        aad_addr: int = 0,
    ):
        """Initialize HSE AEAD cipher scheme parameters.

        Creates an AEAD (Authenticated Encryption with Associated Data) cipher scheme
        configuration for HSE cryptographic operations. This scheme supports encryption
        with authentication using initialization vectors, authentication tags, and
        additional authenticated data.

        :param auth_cipher_mode: Authentication cipher mode identifier, defaults to 0
        :param tag_length: Length of the authentication tag in bytes, defaults to 0
        :param tag_addr: Memory address where the authentication tag is stored, defaults to 0
        :param iv_length: Length of the initialization vector/nonce in bytes, defaults to 0
        :param iv_addr: Memory address where the initialization vector is stored, defaults to 0
        :param aad_length: Length of additional authenticated data in bytes, defaults to 0
        :param aad_addr: Memory address where additional authenticated data is stored, defaults to 0
        """
        self.auth_cipher_mode: int = auth_cipher_mode
        self.tag_length: int = tag_length
        self.tag_addr: int = tag_addr
        self.iv_length: int = iv_length
        self.iv_addr: int = iv_addr
        self.aad_length: int = aad_length
        self.aad_addr: int = aad_addr

    def export(self) -> bytes:
        """Convert to bytes."""
        return pack(
            self.FORMAT,
            self.auth_cipher_mode,
            0,
            self.tag_length,
            self.tag_addr,
            self.iv_length,
            self.iv_addr,
            self.aad_length,
            self.aad_addr,
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Load from bytes."""
        values = unpack(cls.FORMAT, data)
        return cls(
            auth_cipher_mode=values[0],
            tag_length=values[2],
            tag_addr=values[3],
            iv_length=values[4],
            iv_addr=values[5],
            aad_length=values[6],
            aad_addr=values[7],
        )


class KeyContainer:
    """HSE Key Container structure for authenticated key import."""

    def __init__(
        self,
        key_container_len: int = 0,
        key_container_addr: int = 0,
        auth_key_handle: Optional[KeyHandle] = None,
        auth_scheme: Optional[AuthScheme] = None,
        auth_len: Optional[tuple] = None,
        auth_addr: Optional[tuple] = None,
    ):
        """Initialize HSE Key Container for authenticated key import operations.

        The Key Container structure is used for importing keys that require authentication
        verification. It encapsulates the container metadata, authentication parameters,
        and tag information needed for secure key import operations in HSE.

        :param key_container_len: Length of the key container data in bytes, defaults to 0
        :param key_container_addr: Memory address where the key container data is located, defaults to 0
        :param auth_key_handle: Handle of the key used for authentication verification,
                               defaults to invalid handle if not specified
        :param auth_scheme: Authentication scheme (MAC or signature) used to verify the container,
                           defaults to None for unauthenticated import
        :param auth_len: Tuple of authentication tag lengths (tag1_len, tag2_len) in bytes,
                        defaults to (0, 0) if not specified
        :param auth_addr: Tuple of authentication tag addresses (tag1_addr, tag2_addr) in memory,
                         defaults to (0, 0) if not specified
        """
        # Container metadata
        self.key_container_len: int = key_container_len
        self.key_container_addr: int = key_container_addr
        # Authentication parameters
        self.auth_key_handle: KeyHandle = auth_key_handle or KeyHandle(KeyHandle.INVALID_KEY_HANDLE)
        self.auth_scheme: Optional[AuthScheme] = auth_scheme
        # Authentication tag parameters
        self.auth_len: tuple = auth_len or (0, 0)
        if len(self.auth_len) != 2:
            raise SPSDKError("auth_len must be a tuple of 2 integers")
        self.auth_addr: tuple = auth_addr or (0, 0)
        if len(self.auth_addr) != 2:
            raise SPSDKError("auth_addr must be a tuple of 2 integers")

    def export(self) -> bytes:
        """Convert key container to bytes."""
        ret = pack(
            LITTLE_ENDIAN + UINT16 + UINT8 + UINT8 + UINT32 + UINT32,
            self.key_container_len,
            0,
            0,
            self.key_container_addr,
            self.auth_key_handle.handle,
        )
        ret += self.auth_scheme.export() if self.auth_scheme else bytes(12)
        ret += pack(
            LITTLE_ENDIAN + UINT16 + UINT16 + UINT32 + UINT32,
            self.auth_len[0],
            self.auth_len[1],
            self.auth_addr[0],
            self.auth_addr[1],
        )

        return ret

    def get_size(self) -> int:
        """Get size of the key container."""
        auth_scheme_size = self.auth_scheme.size if self.auth_scheme else 12
        return (
            calcsize(LITTLE_ENDIAN + UINT16 + UINT8 + UINT8 + UINT32 + UINT32)
            + auth_scheme_size
            + calcsize(LITTLE_ENDIAN + UINT16 + UINT16 + UINT32 + UINT32)
        )


class CoreId(SpsdkEnum):
    """HSE Core enumeration.

    Defines the available application cores that can be managed by HSE
    for Core Reset operations and secure boot configurations.
    """

    CORE_M7_0 = (0, "M7_0", "Core M7_0")
    CORE_M7_1 = (1, "M7_1", "Core M7_1")
    CORE_M7_2 = (2, "M7_2", "Core M7_2")
    CORE_M7_3 = (3, "M7_3", "Core M7_3")

    @classmethod
    def get_available_core_ids(cls, family: FamilyRevision) -> list[Self]:
        """Get available cores for the given family."""
        db = get_db(family)
        available_core_labels = db.get_list(DatabaseManager.HSE, "core_ids")
        return [cls.from_label(label) for label in available_core_labels]
