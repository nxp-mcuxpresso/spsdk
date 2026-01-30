#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""HSE Secure Memory Region (SMR) module.

This module provides classes and utilities for managing HSE (Hardware Security Engine)
Secure Memory Regions, including SMR entries, authentication schemes, and decryption
parameters. It supports various authentication methods (ECDSA, EdDSA, RSA, CMAC, HMAC, GMAC)
and encryption options for secure boot and runtime verification.
"""

import logging
import struct
from abc import abstractmethod
from dataclasses import dataclass
from struct import pack
from typing import Any, Optional, Type

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKParsingError, SPSDKValueError
from spsdk.image.hse.common import KeyHandle
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import value_to_int
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)

LITTLE_ENDIAN = "<"
UINT8 = "B"
UINT16 = "H"
UINT32 = "L"
INT32 = "l"
UINT64 = "Q"


class SmrConfigFlags(SpsdkEnum):
    """Enumeration of HSE SMR configuration flags.

    Defines the available configuration flags for Secure Memory Region entries.
    """

    QSPI_FLASH = (0, "QSPI_FLASH", "SMR source is in QSPI Flash")
    SD_FLASH = (2, "SD_FLASH", "SMR source is in SD Flash")
    MMC_FLASH = (3, "MMC_FLASH", "SMR source is in MMC Flash")
    INSTALL_AUTH = (4, "INSTALL_AUTH", "Use installation authentication for verification")
    AUTH_AAD = (8, "AUTH_AAD", "Authentication is computed over [AAD || Plain] image")


@dataclass
class SmrDecrypt:
    """Parameters to decrypt an encrypted SMR.

    This dataclass encapsulates the parameters needed for SMR (Secure Memory Region) decryption,
    including key handle, GMAC tag, and AAD (Additional Authenticated Data) information.

    The decrypt_key_handle can be initialized as None, but will be automatically set to
    HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED in __post_init__ if not provided, ensuring it's
    always a valid KeyHandle instance after initialization.
    """

    FORMAT = LITTLE_ENDIAN + UINT32 + UINT8 + UINT8 * 3 + UINT32

    HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED = 0x00000000

    decrypt_key_handle: KeyHandle = KeyHandle.from_handle(HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED)
    """The key handle referencing the decryption key. If None, SMR is not encrypted."""

    gmac_tag_addr: int = 0
    """Address of the Tag used for GCM. If set to 0, AES-CTR is used for decryption."""

    aad_length: int = 0
    """Optional - the length in bytes of the Authenticated Additional Data (AAD)."""

    aad_addr: int = 0
    """Optional - the address of AAD used for AEAD."""

    def __post_init__(self) -> None:
        """Validate the parameters after initialization."""
        # Only validate other fields if decryption is actually used
        if self.is_decryption_used:
            if self.aad_length != 0 and self.aad_length != 64 and self.aad_length != 128:
                raise SPSDKValueError("aad_length must be 0, 64, or 128 bytes")
            if self.aad_length > 0 and self.aad_addr == 0:
                raise SPSDKValueError("aad_addr must be provided when aad_length is non-zero")
            if self.aad_length > 0 and self.gmac_tag_addr == 0:
                raise SPSDKValueError("pGmacTag must be provided when AAD is used")

    @property
    def is_decryption_used(self) -> bool:
        """Check if SMR decryption is used.

        :return: True if decryption is used, False otherwise
        """
        if self.decrypt_key_handle is None:
            return False
        handle_value = self.decrypt_key_handle.export()
        return (
            int.from_bytes(handle_value, byteorder="little")
            != self.HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED
        )

    def export(self) -> bytes:
        """Export SMR decrypt object to binary format.

        :return: Binary representation of the SMR decrypt object
        """
        assert isinstance(self.decrypt_key_handle, KeyHandle)
        result = self.decrypt_key_handle.export()
        result += pack(
            self.FORMAT,
            self.gmac_tag_addr,
            self.aad_length,
            0,
            0,
            0,
            self.aad_addr,
        )
        return result

    @classmethod
    def get_size(cls) -> int:
        """Get the size of the SMR decrypt structure.

        :return: Size in bytes
        """
        return KeyHandle.get_size() + struct.calcsize(cls.FORMAT)

    @property
    def size(self) -> int:
        """Get the size of the SMR decrypt structure.

        :return: Size in bytes
        """
        return self.get_size()

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SMR decrypt parameters from binary data.

        :param data: Binary data containing SMR decrypt parameters
        :return: SmrDecrypt instance
        :raises SPSDKParsingError: If data is invalid
        """
        if len(data) < cls.get_size():
            raise SPSDKParsingError(
                f"Insufficient data for SMR decrypt parameters. Expected {cls.get_size()} bytes, got {len(data)}"
            )

        # Parse decrypt key handle
        decrypt_key_handle = KeyHandle.parse(data[: KeyHandle.get_size()])

        # Parse remaining fields
        gmac_tag_addr, aad_length, _, _, _, aad_addr = struct.unpack(
            LITTLE_ENDIAN + UINT32 + UINT8 + UINT8 * 3 + UINT32,
            data[KeyHandle.get_size() : cls.get_size()],
        )

        return cls(
            decrypt_key_handle=decrypt_key_handle,
            gmac_tag_addr=gmac_tag_addr,
            aad_length=aad_length,
            aad_addr=aad_addr,
        )


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


class CipherAlgo(SpsdkEnum):
    """Enumeration of HSE cipher algorithms."""

    NULL = (0x00, "NULL", "NULL cipher")
    AES = (0x10, "AES", "AES cipher")


class HashAlgo(SpsdkEnum):
    """Enumeration of HSE hash algorithms."""

    NULL = (0, "NULL", "None")
    RESERVED1 = (1, "RESERVED1", "Reserved (MD5 obsolete)")
    SHA_1 = (2, "SHA_1", "SHA1 hash")
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
        result = pack(self.HEADER_FORMAT, self.AUTH_SCH.tag, 0, 0, 0)

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
        return pack(self.SCH_FORMAT, self.hash_algo.tag, 0, 0, 0)

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
        return pack(
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
        return pack(
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
        return pack(self.SCH_FORMAT, self.hash_algo.tag, 0, 0, 0)

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
        return pack(self.SCH_FORMAT, self.cipher_algo.tag, 0, 0, 0)

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
        return pack(self.SCH_FORMAT, self.hash_algo.tag, 0, 0, 0)

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
        return pack(
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
        return pack(self.SCH_FORMAT, 0, 0, 0, 0)

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


class SmrEntry(FeatureBaseClass):
    """HSE Secure Memory Region Entry.

    This class represents a Secure Memory Region (SMR) entry which defines
    the properties of a memory region that needs to be verified during boot
    or runtime phase.
    """

    FEATURE = DatabaseManager.HSE
    SUB_FEATURE = "smr"

    def __init__(
        self,
        family: FamilyRevision,
        auth_scheme: AuthScheme,
        smr_src_addr: int,
        smr_size: int,
        smr_dest: int,
        auth_key_handle: KeyHandle,
        config_flags: SmrConfigFlags = SmrConfigFlags.QSPI_FLASH,
        check_period: int = 0,
        inst_auth_tag: tuple[int, int] = (0, 0),
        version_offset: int = 0,
        smr_decrypt: Optional[SmrDecrypt] = None,
    ) -> None:
        """Initialize the key information structure.

        :param family: Device family
        :param auth_scheme: Key flags defining key properties
        :param smr_src_addr: Source address where the SMR needs to be loaded from. This address must be absolute address
        :param smr_size: The size in bytes of the SMR to be loaded/verified
        :param smr_dest: Destination address of SMR (where to copy the SMR after authentication)
        :param config_flags: Configuration flags of SMR entry
        :param check_period: If check_period != 0, HSE verify the SMR entry periodically (in background)
        :param auth_key_handle: The key handle used to check the authenticity of the plaintext SMR
        :param inst_auth_tag_addrs: The location in external flash of the initial proof of authenticity over SMR
        :param version_offset: The offset in SMR where the image version can be found.May be used to provide the SMR version which offers anti-rollback protection for the image
        :param smr_decrypt: Specifies the parameters for SMR decryption
        """
        self.family = family
        self.auth_scheme = auth_scheme
        self.smr_src_addr = smr_src_addr
        self.smr_size = smr_size
        self.smr_dest = smr_dest
        self.config_flags = config_flags
        self.check_period = check_period
        self.auth_key_handle = auth_key_handle
        self.inst_auth_tag_addrs = inst_auth_tag
        self.version_offset = version_offset
        self.smr_decrypt = smr_decrypt or SmrDecrypt()

    def __repr__(self) -> str:
        """Return representation of SMR entry.

        :return: String representation for debugging
        """
        return (
            f"SmrEntry("
            f"family={self.family}, "
            f"smr_src_addr=0x{self.smr_src_addr:08X}, "
            f"smr_size=0x{self.smr_size:08X}, "
            f"smr_dest=0x{self.smr_dest:08X}, "
            f"config_flags={self.config_flags.label}, "
            f"check_period={self.check_period}, "
            f"auth_key_handle={self.auth_key_handle.handle:08X}, "
            f"auth_scheme={self.auth_scheme.AUTH_SCH.label}, "
            f"version_offset={self.version_offset}"
            f")"
        )

    def verify(self) -> Verifier:
        """Verify SMR entry data and return verification results.

        This method performs comprehensive verification of the Secure Memory Region (SMR) entry,
        including validation of addresses, sizes, alignment, check period, and version offset.

        :return: Verifier object containing detailed verification results and any warnings or errors.
        """
        ret = Verifier("SMR Entry")
        # Validate source address
        if not isinstance(self.smr_src_addr, int) or self.smr_src_addr <= 0:
            ret.add_record(
                "SMR Source Address",
                VerifierResult.ERROR,
                "SMR source address must be a positive integer",
            )
        else:
            ret.add_record(
                "SMR Source Address",
                VerifierResult.SUCCEEDED,
                f"Valid source address: {hex(self.smr_src_addr)}",
            )

        # Validate SMR size
        if not isinstance(self.smr_size, int) or self.smr_size <= 0:
            ret.add_record("SMR Size", VerifierResult.ERROR, "SMR size must be a positive integer")
        else:
            ret.add_record(
                "SMR Size", VerifierResult.SUCCEEDED, f"Valid SMR size: {self.smr_size} bytes"
            )

        # Validate destination address if provided
        if self.smr_dest != 0:
            if not isinstance(self.smr_dest, int) or self.smr_dest < 0:
                ret.add_record(
                    "SMR Destination Address",
                    VerifierResult.ERROR,
                    "SMR destination address must be a non-negative integer",
                )
            else:
                # Check alignment for HSE_B
                if self.smr_dest % 16 != 0 or (self.smr_dest + self.smr_size) % 16 != 0:
                    ret.add_record(
                        "SMR Destination Alignment",
                        VerifierResult.ERROR,
                        "SMR destination address and (destination + size) must be aligned to 16 bytes",
                    )
                else:
                    ret.add_record(
                        "SMR Destination Address",
                        VerifierResult.SUCCEEDED,
                        f"Valid destination address: {hex(self.smr_dest)}",
                    )

        # Validate check period
        if self.check_period == 0xFFFFFFFF:
            ret.add_record(
                "Check Period", VerifierResult.ERROR, "Check period value 0xFFFFFFFF is invalid"
            )
        elif self.check_period != 0:
            if self.smr_dest == 0:
                ret.add_record(
                    "Check Period Configuration",
                    VerifierResult.ERROR,
                    "If check_period is non-zero, smr_dest must be non-zero",
                )
            if self.config_flags != 0:
                ret.add_record(
                    "Check Period Configuration",
                    VerifierResult.ERROR,
                    "If check_period is non-zero, config_flags must be zero",
                )
            if self.smr_dest != 0 and self.config_flags == 0:
                ret.add_record(
                    "Check Period",
                    VerifierResult.SUCCEEDED,
                    f"Periodic verification enabled: every {self.check_period * 100}ms",
                )
        else:
            ret.add_record(
                "Check Period", VerifierResult.SUCCEEDED, "Periodic verification disabled"
            )

        # Validate version offset if provided
        if self.version_offset != 0:
            if not (4 <= self.version_offset <= self.smr_size - 4):
                ret.add_record(
                    "Version Offset",
                    VerifierResult.ERROR,
                    f"Version offset must be in range [4, {self.smr_size - 4}]",
                )
            elif self.version_offset % 4 != 0:
                ret.add_record(
                    "Version Offset Alignment",
                    VerifierResult.ERROR,
                    "Version offset must be aligned to 4 bytes",
                )
            else:
                ret.add_record(
                    "Version Offset",
                    VerifierResult.SUCCEEDED,
                    f"Anti-rollback enabled at offset {hex(self.version_offset)}",
                )
        else:
            ret.add_record(
                "Version Offset", VerifierResult.SUCCEEDED, "Anti-rollback protection not used"
            )

        return ret

    def export(self) -> bytes:
        """Export the SMR entry to binary format.

        :return: Binary representation of the SMR entry
        """
        # Pack the basic fields
        result = pack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT8 + UINT8 * 3 + UINT32,
            self.smr_src_addr,
            self.smr_size,
            self.smr_dest,
            self.config_flags.tag,
            0,
            0,
            0,
            self.check_period,
        )
        result += self.auth_key_handle.export()
        result += self.auth_scheme.export()
        # Pack the installation authentication tags
        result += pack(
            LITTLE_ENDIAN + UINT32 + UINT32,
            self.inst_auth_tag_addrs[0],
            self.inst_auth_tag_addrs[1],
        )
        # Pack the SMR decrypt parameters
        result += self.smr_decrypt.export()
        # Pack the version offset
        result += pack(LITTLE_ENDIAN + UINT32, self.version_offset)

        return result

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse SMR entry from binary data.

        :param data: Binary data containing the SMR entry
        :param family: Device family revision
        :return: SmrEntry instance
        :raises SPSDKParsingError: If data is invalid or insufficient
        """
        offset = 0
        min_size = struct.calcsize(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT8 + UINT8 * 3 + UINT32
        )

        if len(data) < min_size:
            raise SPSDKParsingError(
                f"Insufficient data for SMR entry. Expected at least {min_size} bytes, got {len(data)}"
            )

        # Parse basic fields
        (
            smr_src_addr,
            smr_size,
            smr_dest,
            config_flags_tag,
            _,  # reserved
            _,  # reserved
            _,  # reserved
            check_period,
        ) = struct.unpack(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT8 + UINT8 * 3 + UINT32,
            data[offset : offset + min_size],
        )
        offset += min_size

        # Parse configuration flags
        try:
            config_flags = SmrConfigFlags.from_tag(config_flags_tag)
        except SPSDKKeyError:
            raise SPSDKParsingError(f"Invalid SMR configuration flags: 0x{config_flags_tag:02X}")

        # Parse authentication key handle (4 bytes)
        key_handle_size = KeyHandle.get_size()
        auth_key_handle = KeyHandle.parse(data[offset : offset + key_handle_size])
        offset += key_handle_size

        # Parse authentication scheme (header + scheme-specific data)
        auth_scheme = AuthScheme.parse(data[offset:])
        offset += auth_scheme.get_size()

        # Parse installation authentication tags (2 x 4 bytes)
        if len(data) < offset + 8:
            raise SPSDKParsingError("Insufficient data for installation authentication tags")

        inst_auth_tag_0, inst_auth_tag_1 = struct.unpack(
            LITTLE_ENDIAN + UINT32 + UINT32, data[offset : offset + 8]
        )
        inst_auth_tag = (inst_auth_tag_0, inst_auth_tag_1)
        offset += 8

        # Parse SMR decrypt parameters
        smr_decrypt = SmrDecrypt.parse(data[offset:])
        offset += smr_decrypt.size

        # Parse version offset (4 bytes)
        if len(data) < offset + 4:
            raise SPSDKParsingError("Insufficient data for version offset")

        version_offset = struct.unpack(LITTLE_ENDIAN + UINT32, data[offset : offset + 4])[0]

        return cls(
            family=family,
            auth_scheme=auth_scheme,
            smr_src_addr=smr_src_addr,
            smr_size=smr_size,
            smr_dest=smr_dest,
            auth_key_handle=auth_key_handle,
            config_flags=config_flags,
            check_period=check_period,
            inst_auth_tag=inst_auth_tag,
            version_offset=version_offset,
            smr_decrypt=smr_decrypt,
        )

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: The CPU/MPU
        :return: List of validation schemas.
        """
        schemas = get_schema_file(DatabaseManager.HSE)
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families(), family=family
        )
        return [family_schema, schemas["smr"]]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load SMR entry from configuration.

        :param config: Configuration object containing SMR entry settings
        :return: SmrEntry instance
        :raises SPSDKValueError: If configuration is invalid
        """
        # Get family
        family = config.get_family()

        # Get basic required fields
        smr_src_addr = config.get_int("smrSrcAddr")
        smr_size = config.get_int("smrSize")
        smr_dest = config.get_int("smrDest", default=0)

        # Get configuration flags
        config_flags_str = config.get_str("configFlags", default="QSPI_FLASH")
        config_flags = SmrConfigFlags.from_label(config_flags_str)

        # Get check period
        check_period = config.get_int("checkPeriod", default=0)

        # Get authentication key handle
        auth_key_handle = KeyHandle.load_from_config(config.get_config("authKeyHandle"))

        # Get authentication scheme
        auth_scheme = None
        auth_scheme_cfg = config.get_config("authScheme")
        for scheme, sch_class in AuthScheme.auth_schemes().items():
            if scheme.label.lower() in auth_scheme_cfg:
                auth_scheme = sch_class.load_from_config(
                    auth_scheme_cfg.get_config(scheme.label.lower())
                )
                break
        if auth_scheme is None:
            raise SPSDKValueError(
                "No valid authentication scheme found in configuration. "
                f"Expected one of: {','.join([s.label.lower() for s in AuthScheme.auth_schemes().keys()])}"
            )

        # Get optional installation authentication tag
        inst_auth_tag_list = config.get_list("instAuthTagAddrs", default=[0, 0])
        inst_auth_tag = (value_to_int(inst_auth_tag_list[0]), value_to_int(inst_auth_tag_list[1]))

        # Get optional SMR decryption parameters
        smr_decrypt = None
        if "smrDecrypt" in config:
            smr_decrypt_cfg = config.get_config("smrDecrypt")
            decrypt_key_handle = KeyHandle.load_from_config(
                smr_decrypt_cfg.get_config("decryptKeyHandle")
            )
            gmac_tag_addr = smr_decrypt_cfg.get_int("gmacTagAddr", default=0)
            aad_length = smr_decrypt_cfg.get_int("aadLength", default=0)
            aad_addr = smr_decrypt_cfg.get_int("aadAddr", default=0)

            smr_decrypt = SmrDecrypt(
                decrypt_key_handle=decrypt_key_handle,
                gmac_tag_addr=gmac_tag_addr,
                aad_length=aad_length,
                aad_addr=aad_addr,
            )

        # Get optional version offset
        version_offset = config.get_int("versionOffset", default=0)

        return cls(
            family=family,
            auth_scheme=auth_scheme,
            smr_src_addr=smr_src_addr,
            smr_size=smr_size,
            smr_dest=smr_dest,
            auth_key_handle=auth_key_handle,
            config_flags=config_flags,
            check_period=check_period,
            inst_auth_tag=inst_auth_tag,
            version_offset=version_offset,
            smr_decrypt=smr_decrypt,
        )

    def __str__(self) -> str:
        """Return string representation of SMR entry.

        :return: Human-readable string representation
        """
        lines = [
            "HSE Secure Memory Region Entry:",
            f"  Family: {self.family}",
            f"  Source Address: 0x{self.smr_src_addr:08X}",
            f"  Size: 0x{self.smr_size:08X} ({self.smr_size} bytes)",
            (
                f"  Destination Address: 0x{self.smr_dest:08X}"
                if self.smr_dest != 0
                else "  Destination Address: Not used (in-place verification)"
            ),
            f"  Configuration Flags: {self.config_flags.label} ({self.config_flags.description})",
        ]

        if self.check_period != 0:
            lines.append(f"  Periodic Verification: Every {self.check_period * 100}ms")
        else:
            lines.append("  Periodic Verification: Disabled")

        lines.append(f"  Authentication Key: {self.auth_key_handle}")
        lines.append(f"  Authentication Scheme: {self.auth_scheme}")

        # Installation authentication tag
        if self.inst_auth_tag_addrs[0] != 0 or self.inst_auth_tag_addrs[1] != 0:
            lines.append(f"  Installation Auth Tag[0]: 0x{self.inst_auth_tag_addrs[0]:08X}")
            lines.append(f"  Installation Auth Tag[1]: 0x{self.inst_auth_tag_addrs[1]:08X}")

        # SMR decryption
        if self.smr_decrypt and self.smr_decrypt.decrypt_key_handle.is_valid():
            lines.append("  SMR Decryption: Enabled")
            lines.append(f"    Decryption Key: {self.smr_decrypt.decrypt_key_handle}")
            if self.smr_decrypt.gmac_tag_addr != 0:
                lines.append(f"    GMAC Tag Address: 0x{self.smr_decrypt.gmac_tag_addr:08X}")
            if self.smr_decrypt.aad_length > 0:
                lines.append(f"    AAD Length: {self.smr_decrypt.aad_length} bytes")
                lines.append(f"    AAD Address: 0x{self.smr_decrypt.aad_addr:08X}")

        # Version offset
        if self.version_offset != 0:
            lines.append(f"  Version Offset: 0x{self.version_offset:08X} (Anti-rollback enabled)")
        else:
            lines.append("  Version Offset: Not used")

        return "\n".join(lines)

    def get_config(self, data_path: str = "./") -> Config:
        """Get configuration dictionary from SMR entry.

        :return: Configuration dictionary that can be used to recreate this SMR entry
        """
        config: Config = Config(
            {
                "family": self.family.name,
                "revision": self.family.revision,
                "smrSrcAddr": f"0x{self.smr_src_addr:08X}",
                "smrSize": f"0x{self.smr_size:08X}",
                "smrDest": f"0x{self.smr_dest:08X}",
                "configFlags": self.config_flags.label,
                "checkPeriod": self.check_period,
                "authKeyHandle": self.auth_key_handle.get_config(),
                "authScheme": self.auth_scheme.get_config(),
            }
        )

        # Add installation authentication tag if used
        if self.inst_auth_tag_addrs[0] != 0 or self.inst_auth_tag_addrs[1] != 0:
            config["instAuthTagAddrs"] = [
                f"0x{self.inst_auth_tag_addrs[0]:08X}",
                f"0x{self.inst_auth_tag_addrs[1]:08X}",
            ]

        # Add SMR decryption if used
        if self.smr_decrypt and self.smr_decrypt.decrypt_key_handle.is_valid():
            smr_decrypt_config: dict[str, Any] = {
                "decryptKeyHandle": self.smr_decrypt.decrypt_key_handle.get_config(),
                "gmacTagAddr": f"0x{self.smr_decrypt.gmac_tag_addr:08X}",
                "aadLength": self.smr_decrypt.aad_length,
            }
            if self.smr_decrypt.aad_length > 0:
                smr_decrypt_config["aadAddr"] = f"0x{self.smr_decrypt.aad_addr:08X}"
            config["smrDecrypt"] = smr_decrypt_config

        # Add version offset if used
        if self.version_offset != 0:
            config["versionOffset"] = f"0x{self.version_offset:08X}"
        return config

    @property
    def size(self) -> int:
        """Get the size of this SMR entry structure.

        :return: Size in bytes
        """
        # Basic fields: smr_src_addr(4) + smr_size(4) + smr_dest(4) + config_flags(1) + reserved(3) + check_period(4)
        basic_size = struct.calcsize(
            LITTLE_ENDIAN + UINT32 + UINT32 + UINT32 + UINT8 + UINT8 * 3 + UINT32
        )

        # Auth key handle: 4 bytes
        key_handle_size = KeyHandle.get_size()

        # Auth scheme: variable size depending on scheme type
        auth_scheme_size = self.auth_scheme.size

        # Installation auth tags: 2 x 4 bytes
        inst_auth_tag_size = 8

        # SMR decrypt parameters: 16 bytes
        smr_decrypt_size = self.smr_decrypt.size

        # Version offset: 4 bytes
        version_offset_size = 4

        return (
            basic_size
            + key_handle_size
            + auth_scheme_size
            + inst_auth_tag_size
            + smr_decrypt_size
            + version_offset_size
        )


def prepare_auth_tag_addr_tuple(
    auth_scheme: AuthScheme, auth_tag_addr: tuple, auth_tag_length: tuple
) -> tuple[int, int]:
    """Prepare authentication tag address tuple for SMR entry installation.

    For ECDSA and EdDSA schemes, two authentication tag addresses are required.
    For other schemes (MAC, RSA), only one address is needed, and the second is set to 0.

    If only one address is provided for ECDSA/EdDSA, the second address is calculated
    by adding the first tag length to the first address.

    :param auth_scheme: Authentication scheme that determines address requirements
    :param auth_tag_addr: Tuple of authentication tag addresses (1 or 2 elements)
    :param auth_tag_length: Tuple of authentication tag lengths (used for calculation)

    :return: Tuple of exactly 2 authentication tag addresses (addr1, addr2)
    """
    if not auth_tag_addr:
        raise SPSDKValueError("auth_tag_addr cannot be empty")

    if not auth_tag_length:
        raise SPSDKValueError("auth_tag_length cannot be empty")

    two_values_required = isinstance(auth_scheme, (EcdsaSignScheme, EddsaSignScheme))
    scheme_name = auth_scheme.__class__.__name__
    if two_values_required:
        if len(auth_tag_addr) == 2:
            return auth_tag_addr
        elif len(auth_tag_addr) == 1:
            # Calculate the second auth tag address based on the first address and length
            second_addr = auth_tag_addr[0] + auth_tag_length[0]
            logger.debug(
                f"The auth tag address has been calculated for {scheme_name}: 0x{second_addr:08X}"
            )
            return (auth_tag_addr[0], second_addr)
        else:
            raise SPSDKError(
                f"Invalid auth_tag_addr length for {scheme_name} scheme: {len(auth_tag_addr)}"
            )
    # MAC/RSA schemes require exactly 1 address
    if len(auth_tag_addr) != 1:
        raise SPSDKError(
            f"Invalid auth_tag_addr length for {scheme_name} scheme: {len(auth_tag_addr)}. Expected exactly 1 address"
        )
    return (auth_tag_addr[0], 0)
