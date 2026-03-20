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
from dataclasses import dataclass
from struct import pack
from typing import Any, Callable, Optional, Union

from typing_extensions import Self

from spsdk.crypto.cmac import cmac
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.keys import ECDSASignature, PrivateKeyEcc, PrivateKeyRsa
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.crypto.symmetric import aes_gcm_encrypt
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.hse.common import (
    AuthScheme,
    AuthSchemeEnum,
    EcdsaSignScheme,
    EddsaSignScheme,
    KeyHandle,
)
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import LITTLE_ENDIAN, UINT8, UINT32, Endianness, value_to_int
from spsdk.utils.spsdk_enum import SpsdkIntFlag
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


class SmrConfigFlags(SpsdkIntFlag):
    """Enumeration of HSE SMR configuration flags.

    Defines the available configuration flags for Secure Memory Region entries.
    """

    QSPI_FLASH = 0
    SD_FLASH = 2
    MMC_FLASH = 3
    INSTALL_AUTH = 1 << 2
    AUTH_AAD = 1 << 3

    @classmethod
    def get_available_flags(cls, family: FamilyRevision) -> list[Self]:
        """Get available configuration flags for the given family."""
        db = get_db(family)
        available_flags = db.get_list(DatabaseManager.HSE, "smr_config_flags", [])
        if not available_flags:
            return list(cls.__members__.values())
        return [cls.from_label(flag) for flag in available_flags]


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

    decrypt_key_handle: KeyHandle = KeyHandle(HSE_SMR_DECRYPT_KEY_HANDLE_NOT_USED)
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
        config_flags: SmrConfigFlags = SmrConfigFlags(0),
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
            f"config_flags={','.join([f.name or 'Unknown' for f in self.config_flags.to_list()])}, "
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
        flags = self.config_flags.to_list()
        for flag in flags:
            if flag == 0:  # Skip zero flag
                continue
            ret.add_record(
                f"Flag {flag}",
                flag in self.config_flags.get_available_flags(self.family),
                f"Flag {flag} is supported flag for given family {self.family}",
            )
        # Validate source address
        ret.add_record(
            "SMR Source Address",
            isinstance(self.smr_src_addr, int) and self.smr_src_addr > 0,
            "SMR source address must be a positive integer",
        )

        # Validate SMR size
        ret.add_record(
            "SMR Size",
            isinstance(self.smr_size, int) and self.smr_size > 0,
            "SMR size must be a positive integer",
        )

        # Validate destination address if provided
        ret.add_record(
            "SMR Destination Address",
            isinstance(self.smr_dest, int) and self.smr_dest >= 0,
            "SMR destination address must be a non-negative integer",
        )
        if self.smr_dest != 0:
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
        ret.add_record(
            "Authentication Scheme",
            self.auth_scheme.AUTH_SCH in AuthSchemeEnum.get_available_schemes(self.family),
            f"Authentication scheme {self.auth_scheme.AUTH_SCH} not supported.",
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
            self.config_flags.value,
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
        config_flags = SmrConfigFlags(config_flags_tag)
        if config_flags.has_unknown_flags:
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
        available_schemes = AuthSchemeEnum.get_available_schemes(family)
        # Update the schema with filtered schemes
        schemas["smr"]["properties"]["authScheme"]["oneOf"] = [
            sch
            for sch in schemas["smr"]["properties"]["authScheme"]["oneOf"]
            if AuthSchemeEnum.from_label(list(sch["properties"])[0]) in available_schemes
        ]
        config_flags = [flag.name for flag in SmrConfigFlags.get_available_flags(family)]
        schemas["smr"]["properties"]["configFlags"]["items"]["enum"] = config_flags
        schemas["smr"]["properties"]["configFlags"]["enum_template"] = config_flags
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
        config_flags = SmrConfigFlags.from_list(config.get_list("configFlags", []))

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
            f"  Configuration Flags: {','.join([f.name or 'Unknown' for f in self.config_flags.to_list()])}",
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
                "configFlags": [flag.name for flag in self.config_flags.to_list()],
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

    def update_auth_tag_addrs(
        self, auth_tag: Optional[bytes], auth_tag_base_addr: Optional[int]
    ) -> None:
        """Update authentication tag addresses in the SMR entry.

        This method updates the installation authentication tag addresses based on the provided
        authentication tag data and base address. For ECDSA/EdDSA schemes, it calculates
        separate addresses for the r and s components. For other schemes (MAC-based and RSA),
        only the first address is used.

        Important notes:

        - For ECDSA/EdDSA: Sets both inst_auth_tag_addrs[0] (r component) and
          inst_auth_tag_addrs[1] (s component)
        - For MAC/RSA: Sets only inst_auth_tag_addrs[0], inst_auth_tag_addrs[1] remains 0
        - Logs a warning if no authentication tag addresses are configured

        :param auth_tag: The authentication tag bytes to analyze for length calculation.
                        If None or empty, no update is performed (pre-installed tags).
        :param auth_tag_base_addr: The base address where the authentication tag should be stored.
                            If None, the existing addresses in the SMR entry are used.
        """
        if not auth_tag:  # no auth_tag is used or it is pre-installed
            return
        # inst_auth_tag_addrs must be defined either in smr or on command line
        if auth_tag_base_addr and self.inst_auth_tag_addrs == (0, 0):
            tag_lengths = self.get_auth_tag_lengths(auth_tag)
            self.inst_auth_tag_addrs = (
                auth_tag_base_addr,
                0 if tag_lengths[1] == 0 else auth_tag_base_addr + tag_lengths[0],
            )
            logger.info("Authentication tag address has been updated in SMR entry")
        if self.inst_auth_tag_addrs == (0, 0):
            logger.warning("Authentication tag address is empty.")

    def get_auth_tag_lengths(self, auth_tag: bytes) -> tuple[int, int]:
        """Get the lengths of authentication tag components.

        This method determines the length(s) of authentication tag components based on the
        authentication scheme used. For ECDSA and EdDSA signature schemes, it returns the
        lengths of both r and s components. For other schemes (MAC-based and RSA), it
        returns the total tag length and zero for the second component.

        :param auth_tag: The authentication tag bytes to analyze
        :return: Tuple containing (first_component_length, second_component_length).
                For ECDSA/EdDSA: (r_length, s_length)
                For MAC/RSA schemes: (total_tag_length, 0)
        """
        two_values_required = isinstance(self.auth_scheme, (EcdsaSignScheme, EddsaSignScheme))
        if two_values_required:
            signature = ECDSASignature.parse(auth_tag)
            r_length = len(
                signature.r.to_bytes(
                    signature.COORDINATE_LENGTHS[signature.ecc_curve], Endianness.BIG.value
                )
            )
            s_length = len(
                signature.s.to_bytes(
                    signature.COORDINATE_LENGTHS[signature.ecc_curve], Endianness.BIG.value
                )
            )
            return (r_length, s_length)
        # For MAC schemes (CMAC, HMAC, GMAC, XCBC-MAC) and RSA signatures
        # Only one tag is used (pInstAuthTag[0])
        return (len(auth_tag), 0)


SmrKeyType = Union[bytes, PrivateKeyEcc, PrivateKeyRsa]


class SmrAuthenticationTag:
    """Class for creating authentication tags for SMR entries.

    This class provides functionality to create authentication tags for Secure Memory Region
    entries based on different authentication schemes including ECDSA, RSA, and various MAC schemes.
    """

    @staticmethod
    def create_auth_tag(
        data: bytes,
        key: Any,
        auth_scheme: Optional[AuthSchemeEnum] = None,
        hash_algorithm: Optional[EnumHashAlgorithm] = None,
    ) -> bytes:
        """Create authentication tag for SMR entry data.

        :param data: Binary data to create authentication tag from
        :param key: Key for authentication (can be bytes for MAC schemes, or private key objects)
        :param auth_scheme: Authentication scheme to use (optional, auto-detected from key type if not provided)
        :param hash_algorithm: Hash algorithm to use for signature schemes
        :return: Authentication tag bytes
        :raises SPSDKError: If key type is unsupported or operation fails
        """
        auth_scheme = SmrAuthenticationTag.get_auth_scheme(auth_scheme, key)
        auth_tag_creator = SmrAuthenticationTag._get_creation_method(auth_scheme)
        return auth_tag_creator(data, key, hash_algorithm)

    @staticmethod
    def get_auth_scheme(auth_scheme: Optional[AuthSchemeEnum], key: SmrKeyType) -> AuthSchemeEnum:
        """Determine the authentication scheme from key type if not explicitly provided.

        This method automatically detects the appropriate authentication scheme based on the
        key type when no explicit scheme is provided. It supports ECC keys (ECDSA), RSA keys
        (RSASSA_PKCS1_V15), and symmetric keys (CMAC as default).

        :param auth_scheme: Authentication scheme to use. If provided, this value is returned directly.
        :param key: Key for authentication. Can be PrivateKeyEcc, PrivateKeyRsa, or bytes.
        :return: Determined authentication scheme
        :raises SPSDKError: If key type is unsupported or cannot be determined

        .. note::
            When key is provided as bytes, the method attempts to parse it as RSA first,
            then ECC, and finally defaults to CMAC for symmetric keys that cannot be parsed
            as asymmetric keys.
        """
        if auth_scheme:
            return auth_scheme
        if isinstance(key, PrivateKeyEcc):
            return AuthSchemeEnum.ECDSA
        if isinstance(key, PrivateKeyRsa):
            return AuthSchemeEnum.RSASSA_PKCS1_V15
        if isinstance(key, bytes):
            try:
                PrivateKeyRsa.parse(key)
                return AuthSchemeEnum.RSASSA_PKCS1_V15
            except SPSDKError:
                pass
            try:
                PrivateKeyEcc.parse(key)
                return AuthSchemeEnum.ECDSA
            except SPSDKError:
                pass
            # For bytes that aren't parseable as keys, assume MAC scheme
            return AuthSchemeEnum.CMAC
        raise SPSDKError(f"Unable to determine authentication scheme for key type: {type(key)}")

    @staticmethod
    def _get_creation_method(auth_scheme_enum: AuthSchemeEnum) -> Callable:
        """Get the method name for creating authentication tags.

        :param auth_scheme_enum: Authentication scheme enumeration
        :return: Method name string
        :raises SPSDKError: If scheme is not supported
        """
        method_map = {
            AuthSchemeEnum.ECDSA: SmrAuthenticationTag._create_ecdsa_signature,
            AuthSchemeEnum.RSASSA_PKCS1_V15: SmrAuthenticationTag._create_rsa_pkcs1_signature,
            AuthSchemeEnum.RSASSA_PSS: SmrAuthenticationTag._create_rsa_pss_signature,
            AuthSchemeEnum.CMAC: SmrAuthenticationTag._create_cmac_tag,
            AuthSchemeEnum.HMAC: SmrAuthenticationTag._create_hmac_tag,
            AuthSchemeEnum.GMAC: SmrAuthenticationTag._create_gmac_tag,
        }

        method_name = method_map.get(auth_scheme_enum)
        if not method_name:
            raise SPSDKError(f"Unsupported authentication scheme: {auth_scheme_enum}")
        return method_name

    @staticmethod
    def _create_cmac_tag(
        data: bytes, key: SmrKeyType, hash_algorithm: Optional[EnumHashAlgorithm] = None
    ) -> bytes:
        """Create CMAC authentication tag."""
        if not isinstance(key, bytes):
            raise SPSDKValueError(
                f"CMAC authentication requires bytes key, got {type(key).__name__}"
            )
        return cmac(key, data)

    @staticmethod
    def _create_hmac_tag(
        data: bytes, key: SmrKeyType, hash_algorithm: Optional[EnumHashAlgorithm] = None
    ) -> bytes:
        """Create HMAC authentication tag."""
        if not isinstance(key, bytes):
            raise SPSDKValueError(
                f"HMAC authentication requires bytes key, got {type(key).__name__}"
            )
        return hmac(key, data, hash_algorithm or EnumHashAlgorithm.SHA256)

    @staticmethod
    def _create_gmac_tag(
        data: bytes, key: SmrKeyType, hash_algorithm: Optional[EnumHashAlgorithm] = None
    ) -> bytes:
        """Create GMAC authentication tag."""
        if not isinstance(key, bytes):
            raise SPSDKValueError(
                f"GMAC authentication requires bytes key, got {type(key).__name__}"
            )
        return aes_gcm_encrypt(key, b"", bytes(12), data)[-16:]

    @staticmethod
    def _create_rsa_pss_signature(
        data: bytes, key: SmrKeyType, hash_algorithm: Optional[EnumHashAlgorithm] = None
    ) -> bytes:
        """Create RSA-PSS signature."""
        if isinstance(key, bytes):
            key = PrivateKeyRsa.parse(key)
        if not isinstance(key, PrivateKeyRsa):
            raise SPSDKValueError(
                f"RSA PSS signature requires PrivateKeyRsa key, got {type(key).__name__}"
            )
        return key.sign(data, algorithm=hash_algorithm, pss_padding=True)

    @staticmethod
    def _create_rsa_pkcs1_signature(
        data: bytes, key: SmrKeyType, hash_algorithm: Optional[EnumHashAlgorithm] = None
    ) -> bytes:
        """Create RSA PKCS1v15 signature."""
        if isinstance(key, bytes):
            key = PrivateKeyRsa.parse(key)
        if not isinstance(key, PrivateKeyRsa):
            raise SPSDKValueError(
                f"RSA PKCS1v15 signature requires PrivateKeyRsa key, got {type(key).__name__}"
            )
        return key.sign(data, algorithm=hash_algorithm, pss_padding=False)

    @staticmethod
    def _create_ecdsa_signature(
        data: bytes, key: SmrKeyType, hash_algorithm: Optional[EnumHashAlgorithm] = None
    ) -> bytes:
        """Create ECDSA signature."""
        if isinstance(key, bytes):
            key = PrivateKeyEcc.parse(key)
        if not isinstance(key, PrivateKeyEcc):
            raise SPSDKValueError(
                f"ECDSA signature requires PrivateKeyEcc key, got {type(key).__name__}"
            )
        return key.sign(data, algorithm=hash_algorithm)
