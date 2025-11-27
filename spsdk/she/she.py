#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK SHE (Secure Hardware Extension) operations and utilities.

This module provides comprehensive functionality for working with SHE protocol,
including boot modes, key management, flash partition handling, and cryptographic
operations. It supports key derivation, updates, and boot MAC generation for
secure automotive applications.
"""

from dataclasses import dataclass, field
from typing import Any

from bitstring import Bits
from typing_extensions import Self

from spsdk.crypto.cmac import cmac
from spsdk.crypto.miyaguchi_preneel import mp_compress
from spsdk.crypto.symmetric import aes_cbc_encrypt, aes_ecb_encrypt
from spsdk.exceptions import SPSDKError
from spsdk.utils.abstract_features import ConfigBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import swap_endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class SHEBootMode(SpsdkEnum):
    """SHE Boot Mode enumeration for Secure Hardware Extension.

    This enumeration defines the available boot modes for SHE (Secure Hardware Extension)
    operations, including strict, serial, and parallel boot configurations.
    """

    STRICT = (0x00, "strict", "Strict Boot Mode")
    SERIAL = (0x01, "serial", "Serial Boot Mode")
    PARALLEL = (0x02, "parallel", "Parallel Boot Mode")


class SHEMaxKeyCountCode(SpsdkEnum):
    """SHE maximum key count configuration enumeration.

    This enumeration defines the supported maximum key count configurations
    for SHE (Secure Hardware Extension) operations, ranging from disabled
    CSEc to various key capacity limits.
    """

    NONE = (0x00, "0", "0 Keys, CSEc is disabled")
    FIVE = (0x01, "5", "5 Keys")
    TEN = (0x02, "10", "10 Keys")
    TWENTY = (0x03, "20", "20 Keys")


class SHEFlashPartitionSizeCode(SpsdkEnum):
    """SHE Flash Partition Size Code enumeration.

    This enumeration defines the available flash partition size codes used in SHE (Secure Hardware
    Extension) operations. Each code represents a specific flash partition size configuration
    supported by the SHE module.
    """

    SIXTY_FOUR = (0x00, "64", "64 KB Flash Partition")
    FORTY_EIGHT = (0x01, "48", "48 KB Flash Partition")
    THIRTY_TWO = (0x02, "32", "32 KB Flash Partition")
    NONE = (0x03, "0", "No Flash Partition")


class SHEKeyID(SpsdkEnum):
    """SHE Key ID enumeration for cryptographic operations.

    This enumeration defines the standardized key identifiers used in SHE (Secure Hardware Extension)
    cryptographic operations, including master keys, boot authentication keys, and user-defined keys
    for secure automotive applications.
    """

    MASTER_ECU_KEY = (0x01, "MASTER_ECU_KEY")
    BOOT_MAC_KEY = (0x02, "BOOT_MAC_KEY")
    BOOT_MAC = (0x03, "BOOT_MAC")
    RAM_KEY = (0x0F, "RAM_KEY")
    USER_KEY_1 = (0x04, "USER_KEY_1")
    USER_KEY_2 = (0x05, "USER_KEY_2")
    USER_KEY_3 = (0x06, "USER_KEY_3")
    USER_KEY_4 = (0x07, "USER_KEY_4")
    USER_KEY_5 = (0x08, "USER_KEY_5")
    USER_KEY_6 = (0x09, "USER_KEY_6")
    USER_KEY_7 = (0x0A, "USER_KEY_7")
    USER_KEY_8 = (0x0B, "USER_KEY_8")
    USER_KEY_9 = (0x0C, "USER_KEY_9")
    USER_KEY_10 = (0x0D, "USER_KEY_10")
    USER_KEY_11 = (0x14, "USER_KEY_11")
    USER_KEY_12 = (0x15, "USER_KEY_12")
    USER_KEY_13 = (0x16, "USER_KEY_13")
    USER_KEY_14 = (0x17, "USER_KEY_14")
    USER_KEY_15 = (0x18, "USER_KEY_15")
    USER_KEY_16 = (0x19, "USER_KEY_16")
    USER_KEY_17 = (0x1A, "USER_KEY_17")


class SHEDeriveKey:
    """SHE key derivation utility for cryptographic operations.

    This class provides key derivation functionality according to SHE (Secure Hardware Extension)
    protocols. It supports derivation of different key types including encryption keys, MAC keys,
    and debug keys using standardized SHE derivation algorithms.
    """

    class KeyType(SpsdkEnum):
        """SHE key type enumeration for cryptographic operations.

        This enumeration defines the different types of keys used in SHE (Secure Hardware Extension)
        key derivation processes, including encryption, MAC, and debug keys.
        """

        ENCRYPTION_KEY = (0x01, "ENC", "Encryption key")
        MAC_KEY = (
            0x02,
            "MAC",
            "Message Authentication Code key",
        )
        DEBUG_KEY = (0x03, "DBG", "Debug key")

    @classmethod
    def derive_key(cls, key: bytes, key_type: KeyType) -> bytes:
        """Derive key using SHE key derivation algorithm.

        This method implements the SHE (Secure Hardware Extension) key derivation
        process by combining the input key with derivation data and applying
        MP compression.

        :param key: Input key bytes to derive from.
        :param key_type: Type of key to derive, determines derivation parameters.
        :return: Derived key bytes after SHE derivation process.
        """
        derivation_data = b"\x01" + bytes([key_type.tag]) + b"SHE\x00"
        return mp_compress(key + derivation_data)

    @classmethod
    def derive_enc_key(cls, key: bytes) -> bytes:
        """Derive encryption key for SHE operations.

        This method derives an encryption key from the provided input key using
        the SHE key derivation algorithm with encryption key type.

        :param key: Input key bytes to derive the encryption key from.
        :return: Derived encryption key as bytes.
        """
        return SHEDeriveKey.derive_key(key=key, key_type=cls.KeyType.ENCRYPTION_KEY)

    @classmethod
    def derive_mac_key(cls, key: bytes) -> bytes:
        """Derive MAC key for SHE operations.

        The method derives a MAC (Message Authentication Code) key from the input key
        using SHE key derivation algorithm with MAC_KEY type specification.

        :param key: Input key bytes to derive MAC key from.
        :return: Derived MAC key as bytes.
        """
        return SHEDeriveKey.derive_key(key=key, key_type=cls.KeyType.MAC_KEY)

    @classmethod
    def derive_debug_key(cls, key: bytes) -> bytes:
        """Derive debug key for SHE operations.

        The method derives a debug key from the provided input key using SHE key derivation
        algorithm with DEBUG_KEY type.

        :param key: Input key bytes to derive debug key from.
        :return: Derived debug key as bytes.
        """
        return SHEDeriveKey.derive_key(key=key, key_type=cls.KeyType.DEBUG_KEY)


@dataclass
class SHEUpdateFlags:
    """SHE key update operation flags container.

    This class represents a collection of boolean flags that control various aspects
    of SHE (Secure Hardware Extension) key update operations, including protection
    settings and operational modes. The flags can be converted to bitstring format
    for hardware communication and loaded from configuration files.
    """

    write_protection: bool = False
    boot_protection: bool = False
    debugger_protection: bool = False
    key_usage: bool = False
    wildcard: bool = False
    verify_only: bool = False

    def get_bits(self) -> Bits:
        """Convert SHE update flags to bitstring representation.

        Creates a concatenated bitstring from all SHE update flag boolean values in the order:
        write_protection, boot_protection, debugger_protection, key_usage, wildcard, verify_only.

        :return: Bitstring representation of all SHE update flags.
        """
        return (
            Bits(bool=self.write_protection)
            + Bits(bool=self.boot_protection)
            + Bits(bool=self.debugger_protection)
            + Bits(bool=self.key_usage)
            + Bits(bool=self.wildcard)
            + Bits(bool=self.verify_only)
        )

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load SHE update configuration from a Config object.

        Creates a new SHE configuration instance by extracting boolean configuration values
        for various protection and usage settings from the provided Config object.

        :param config: Configuration object containing SHE settings with boolean values for
            write_protection, boot_protection, debugger_protection, key_usage, wildcard,
            and verify_only options.
        :return: New SHE configuration instance with settings loaded from config.
        """
        return cls(
            write_protection=config.get_bool("write_protection", False),
            boot_protection=config.get_bool("boot_protection", False),
            debugger_protection=config.get_bool("debugger_protection", False),
            key_usage=config.get_bool("key_usage", False),
            wildcard=config.get_bool("wildcard", False),
            verify_only=config.get_bool("verify_only", False),
        )


@dataclass
class SHEUpdate(ConfigBaseClass):
    """SHE Key Update operation implementation.

    This class manages the Secure Hardware Extension (SHE) key update process,
    handling the generation and verification of cryptographic messages required
    for secure key provisioning in NXP MCUs with SHE support.

    :cvar FEATURE: Feature identifier for SHE SCEC operations.
    """

    FEATURE = "she_scec"
    new_key: bytes
    new_key_id: int
    uid: int = 0
    auth_key_id: int = 1
    auth_key: bytes = 16 * bytes(0xFF)
    counter: int = 1
    flags: SHEUpdateFlags = field(default_factory=SHEUpdateFlags)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load SHEUpdate configuration from a config object.

        Creates a new SHEUpdate instance by parsing configuration parameters including key IDs,
        cryptographic keys, UID, counter, and flags from the provided config object.

        :param config: Configuration object containing SHE update parameters
        :return: New SHEUpdate instance configured with the provided parameters
        :raises SPSDKError: If new key or authentication key is not exactly 16 bytes
        """
        new_key_id = config.get("key_id")
        new_key = SHEKeyID.from_attr(new_key_id)
        auth_key_id = config.get("auth_key_id", 1)
        auth_key = SHEKeyID.from_attr(auth_key_id)
        new_key_bytes = bytes.fromhex(config.load_secret("key"))
        auth_key_bytes = bytes.fromhex(config.load_secret("auth_key", "FF" * 16))

        if len(new_key_bytes) != 16:
            raise SPSDKError(
                f"New key must be exactly 16 bytes (128 bits), got {len(new_key_bytes)} bytes"
            )
        if len(auth_key_bytes) != 16:
            raise SPSDKError(
                f"Authentication key must be exactly 16 bytes (128 bits), got {len(auth_key_bytes)} bytes"
            )
        return cls(
            new_key=new_key_bytes,
            new_key_id=new_key.tag,
            uid=config.get_int("uid", 0),
            auth_key_id=auth_key.tag,
            auth_key=auth_key_bytes,
            counter=config.get_int("counter", 1),
            flags=SHEUpdateFlags.load_from_config(config=config),
        )

    def _get_ids_data(self) -> bytes:
        """Get IDs data as bytes.

        Constructs a byte representation of the IDs data by concatenating the UID (120 bits),
        new key ID (4 bits), and authentication key ID (4 bits) into a single byte array.

        :return: Concatenated IDs data as bytes containing UID, new key ID, and auth key ID.
        """
        ids_bits = (
            Bits(uint=self.uid, length=120)
            + Bits(uint=self.new_key_id_x, length=4)
            + Bits(uint=self.auth_key_id, length=4)
        )
        return ids_bits.tobytes()

    def get_messages(self) -> tuple[bytes, bytes, bytes]:
        """Generate M1, M2, and M3 update messages for SHE key update protocol.

        Creates the three messages required for secure key update in SHE (Secure Hardware Extension):
        - M1: Contains key identifiers and slot information
        - M2: Contains encrypted counter, flags, and new key data
        - M3: Contains MAC authentication for M1 and M2 messages

        :return: Tuple containing M1, M2, and M3 messages as bytes objects.
        """
        m1 = self._get_ids_data()

        m2_bits = Bits(uint=self.counter, length=28) + self.flags.get_bits() + Bits(94)
        m2_data = m2_bits.tobytes() + self.new_key
        k1 = SHEDeriveKey.derive_enc_key(key=self.auth_key)
        m2 = aes_cbc_encrypt(key=k1, plain_data=m2_data)

        k2 = SHEDeriveKey.derive_mac_key(key=self.auth_key)
        m3 = cmac(key=k2, data=m1 + m2)

        return m1, m2, m3

    def get_verification_messages(self) -> tuple[bytes, bytes]:
        """Generate verification messages M4 and M5 for key update.

        This method creates the verification messages used in the SHE key update protocol.
        M4 contains the key identifier data and encrypted counter information, while M5
        is the MAC authentication code for M4.

        :return: Tuple containing M4 verification message and M5 MAC authentication code.
        """
        k3 = SHEDeriveKey.derive_enc_key(key=self.new_key)
        padded_counter = Bits(uint=self.counter, length=28) + Bits(bool=True) + Bits(99)
        m4_tail = aes_ecb_encrypt(key=k3, plain_data=padded_counter.tobytes())
        m4 = self._get_ids_data() + m4_tail
        k4 = SHEDeriveKey.derive_mac_key(key=self.new_key)
        m5 = cmac(key=k4, data=m4)
        return m4, m5

    def get_blob(self) -> bytes:
        """Get all update messages as a single binary blob.

        This method combines all SHE update and verification messages into a continuous
        binary sequence for transmission or storage.

        :return: Binary data containing concatenated M1, M2, M3, M4, and M5 messages.
        """
        m1, m2, m3 = self.get_messages()
        m4, m5 = self.get_verification_messages()
        return m1 + m2 + m3 + m4 + m5

    def verify_messages(self, m4: bytes, m5: bytes) -> None:
        """Verify M4 and M5 update messages.

        Validates the provided M4 and M5 messages against calculated verification messages
        to ensure data integrity and authenticity.

        :param m4: M4 data message to verify.
        :param m5: M5 CMAC message to verify.
        :raises SPSDKError: When M4 or M5 message verification fails.
        """
        m4_calc, m5_calc = self.get_verification_messages()
        if m4 != m4_calc:
            raise SPSDKError("M4 (data) message is invalid")
        if m5 != m5_calc:
            raise SPSDKError("M5 (cmac) message is invalid")

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for SHE key update configuration.

        Retrieves and configures validation schemas for SHE (Secure Hardware Extension) key update
        operations. The method combines basic schemas with SHE-specific configuration schemas,
        updates family-specific validation rules, and configures allowed authentication key IDs.

        :param family: Target family and revision for schema validation.
        :return: List of validation schema dictionaries for key update configuration.
        """
        sch_basic = cls.get_validation_schemas_basic()
        sch_cfg = get_schema_file(DatabaseManager.SHE_SCEC)
        update_validation_schema_family(
            sch=sch_basic[0]["properties"], devices=cls.get_supported_families(), family=family
        )
        allowed_auth_keys = SHEKeyID.labels()
        allowed_auth_keys.remove(SHEKeyID.BOOT_MAC.label)
        sch_cfg["key_info"]["properties"]["auth_key_id"]["enum"] = allowed_auth_keys
        return sch_basic + [sch_cfg["key_info"], sch_cfg["flags"]]

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        The method retrieves validation schemas for SHE key operations, customizing authentication
        key options based on the specified key type. For BOOT_MAC keys, it allows BOOT_MAC_KEY
        as authenticator, while other keys can use themselves or MASTER_ECU_KEY for authentication.

        :param config: Valid configuration containing key_id and optional auth_key_id settings.
        :return: List of validation schema dictionaries with updated authentication key constraints.
        """
        config.check(cls.get_validation_schemas_basic())
        sch = cls.get_validation_schemas(FamilyRevision.load_from_config(config))
        if "auth_key_id" in config:
            key_id = SHEKeyID.from_label(config["key_id"])
            allowed_auth_keys = [SHEKeyID.MASTER_ECU_KEY.label]

            # Add appropriate additional auth key based on key type
            if key_id == SHEKeyID.BOOT_MAC:
                allowed_auth_keys.append(SHEKeyID.BOOT_MAC_KEY.label)
            else:
                allowed_auth_keys.append(key_id.label)
            sch[1]["properties"]["auth_key_id"]["enum"] = list(set(allowed_auth_keys))
        return sch

    def get_config(self, data_path: str = "./") -> Config:
        """Re-create configuration object from the specified data path.

        This method should reconstruct a configuration object using data from the given path,
        typically used for restoring or loading previously saved configuration settings.

        :param data_path: Path to the directory containing configuration data, defaults to current directory.
        :raises NotImplementedError: This method must be implemented by subclasses.
        :return: Configuration object recreated from the data path.
        """
        raise NotImplementedError()

    @property
    def new_key_id_x(self) -> int:
        """Convert new_key_id to key_id_x by extracting only the four lower bits.

        :return: The corresponding key_id_x value with only the 4 lower bits.
        """
        return self.new_key_id & 0x0F


class SHEBootMac:
    """SHE Boot MAC calculation utility.

    This class provides cryptographic MAC (Message Authentication Code) calculation
    functionality specifically for SHE (Secure Hardware Extension) boot operations,
    handling proper endianness conversion and CMAC computation for authentication.
    """

    @staticmethod
    def calculate(key: bytes, data: bytes) -> bytes:
        """Calculate CMAC for SHE key.

        The method converts input data from little-endian to big-endian format to match
        firmware's byte order expectations, then calculates CMAC with size prefix.

        :param key: Authentication key used for CMAC calculation.
        :param data: Input data for CMAC calculation.
        :return: Calculated CMAC value as bytes.
        """
        # Convert data from little-endian to big-endian format to match firmware's byte order expectations
        data = swap_endianness(data)
        size = len(data) * 8
        prefix = bytes(12) + size.to_bytes(length=4, byteorder="big")
        return cmac(key=key, data=prefix + data)
