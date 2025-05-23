#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for SHE (Secure Hardware Extension) operations."""

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
from spsdk.utils.family import FamilyRevision
from spsdk.utils.spsdk_enum import SpsdkEnum


class SHEMaxKeyCountCode(SpsdkEnum):
    """Enumeration of maximum key counts in SHE operations."""

    NONE = (0x00, "0", "0 Keys, CSEc is disabled")
    FIVE = (0x01, "5", "5 Keys")
    TEN = (0x02, "10", "10 Keys")
    # TWENTY = (0x03, "20", "20 Keys")


class SHEFlashPartitionSizeCode(SpsdkEnum):
    """Enumeration of flash partition codes for SHE operations."""

    # SIXTY_FOUR = (0x00, "64", "64 KB Flash Partition")
    FORTY_EIGHT = (0x01, "48", "48 KB Flash Partition")
    THIRTY_TWO = (0x02, "32", "32 KB Flash Partition")
    NONE = (0x03, "0", "No Flash Partition")


class SHEKeyID(SpsdkEnum):
    """Enumeration of Key IDs for SHE operations."""

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
    # USER_KEY_11 = (0x14, "USER_KEY_11")
    # USER_KEY_12 = (0x15, "USER_KEY_12")
    # USER_KEY_13 = (0x16, "USER_KEY_13")
    # USER_KEY_14 = (0x17, "USER_KEY_14")
    # USER_KEY_15 = (0x18, "USER_KEY_15")
    # USER_KEY_16 = (0x19, "USER_KEY_16")
    # USER_KEY_17 = (0x1A, "USER_KEY_17")


class SHEDeriveKey:
    """Key derivation SHE protocols."""

    class KeyType(SpsdkEnum):
        """Enumeration of key types in SHE key derivation."""

        ENCRYPTION_KEY = (0x01, "ENC", "Encryption key")
        MAC_KEY = (0x02, "MAC", "Message Authentication Code key")
        DEBUG_KEY = (0x03, "DBG", "Debug key")

    @classmethod
    def derive_key(cls, key: bytes, key_type: KeyType) -> bytes:
        """Generic key derivation method for SHE operations.

        :param key: Input key to derive from
        :param key_type: Type of key to derive
        :return: Derived key bytes
        """
        derivation_data = b"\x01" + bytes([key_type.tag]) + b"SHE\x00"
        return mp_compress(key + derivation_data)

    @classmethod
    def derive_enc_key(cls, key: bytes) -> bytes:
        """Derive encryption key Function in SHE operations.

        :param key: Input key to derive from
        :return: Derived encryption key
        """
        return SHEDeriveKey.derive_key(key=key, key_type=cls.KeyType.ENCRYPTION_KEY)

    @classmethod
    def derive_mac_key(cls, key: bytes) -> bytes:
        """Derive MAC key for SHE operations.

        :param key: Input key to derive from
        :return: Derived MAC key
        """
        return SHEDeriveKey.derive_key(key=key, key_type=cls.KeyType.MAC_KEY)

    @classmethod
    def derive_debug_key(cls, key: bytes) -> bytes:
        """Derive debug key for SHE operations.

        :param  key: Input key to derive from
        :return: Derived debug key
        """
        return SHEDeriveKey.derive_key(key=key, key_type=cls.KeyType.DEBUG_KEY)


@dataclass
class SHEUpdateFlags:
    """Flags for SHE key update operation."""

    write_protection: bool = False
    boot_protection: bool = False
    debugger_protection: bool = False
    key_usage: bool = False
    wildcard: bool = False

    def get_bits(self) -> Bits:
        """Convert SHE update flags to bitstring representation."""
        return (
            Bits(bool=self.write_protection)
            + Bits(bool=self.boot_protection)
            + Bits(bool=self.debugger_protection)
            + Bits(bool=self.key_usage)
            + Bits(bool=self.wildcard)
        )

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load SHE update configuration from a Config object."""
        return cls(
            write_protection=config.get_bool("write_protection", False),
            boot_protection=config.get_bool("boot_protection", False),
            debugger_protection=config.get_bool("debugger_protection", False),
            key_usage=config.get_bool("key_usage", False),
            wildcard=config.get_bool("wildcard", False),
        )


@dataclass
class SHEUpdate(ConfigBaseClass):
    """SHE Key Update operation implementation."""

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
        """Load SHEUpdate configuration from a config object."""
        new_key_id = config.get("key_id")
        new_key = SHEKeyID.from_attr(new_key_id)
        auth_key_id = config.get("auth_key_id", 1)
        auth_key = SHEKeyID.from_attr(auth_key_id)
        return cls(
            new_key=bytes.fromhex(config.load_secret("key")),
            new_key_id=new_key.tag,
            uid=config.get_int("uid", 0),
            auth_key_id=auth_key.tag,
            auth_key=bytes.fromhex(config.load_secret("auth_key", "FF" * 16)),
            counter=config.get_int("counter", 1),
            flags=SHEUpdateFlags.load_from_config(config=config),
        )

    def _get_ids_data(self) -> bytes:
        ids_bits = (
            Bits(uint=self.uid, length=120)
            + Bits(uint=self.new_key_id, length=4)
            + Bits(uint=self.auth_key_id, length=4)
        )
        return ids_bits.tobytes()

    def get_messages(self) -> tuple[bytes, bytes, bytes]:
        """Generate M1, M2, and M3 update messages."""
        m1 = self._get_ids_data()

        m2_bits = Bits(uint=self.counter, length=28) + self.flags.get_bits() + Bits(95)
        m2_data = m2_bits.tobytes() + self.new_key
        k1 = SHEDeriveKey.derive_enc_key(key=self.auth_key)
        m2 = aes_cbc_encrypt(key=k1, plain_data=m2_data)

        k2 = SHEDeriveKey.derive_mac_key(key=self.auth_key)
        m3 = cmac(key=k2, data=m1 + m2)

        return m1, m2, m3

    def get_verification_messages(self) -> tuple[bytes, bytes]:
        """Generate verification messages M4 and M5 for key update."""
        k3 = SHEDeriveKey.derive_enc_key(key=self.new_key)
        padded_counter = Bits(uint=self.counter, length=28) + Bits(bool=True) + Bits(99)
        m4_tail = aes_ecb_encrypt(key=k3, plain_data=padded_counter.tobytes())
        m4 = self._get_ids_data() + m4_tail
        k4 = SHEDeriveKey.derive_mac_key(key=self.new_key)
        m5 = cmac(key=k4, data=m4)
        return m4, m5

    def get_blob(self) -> bytes:
        """Get all update messages as a single binary."""
        m1, m2, m3 = self.get_messages()
        m4, m5 = self.get_verification_messages()
        return m1 + m2 + m3 + m4 + m5

    def verify_messages(self, m4: bytes, m5: bytes) -> None:
        """Verify M4 and M5 updates messages.

        :raises SPSDKError: Verification fails.
        """
        m4_calc, m5_calc = self.get_verification_messages()
        if m4 != m4_calc:
            raise SPSDKError("M4 (data) message is invalid")
        if m5 != m5_calc:
            raise SPSDKError("M5 (cmac) message is invalid")

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for SHE key update configuration."""
        sch_basic = cls.get_validation_schemas_basic()
        sch_cfg = get_schema_file(DatabaseManager.SHE_SCEC)
        return sch_basic + [sch_cfg["key_info"], sch_cfg["flags"]]

    def get_config(self, data_path: str = "./") -> Config:
        """Re-create configuration object."""
        raise NotImplementedError()


class SHEBootMac:
    """SHE Boot MAC calculation class.

    This class provides functionality to calculate CMAC for SHE key using boot data.
    """

    @staticmethod
    def calculate(key: bytes, data: bytes) -> bytes:
        """Calculate CMAC for SHE key.

        :param key: Authentication key
        :param data: Input data for CMAC calculation
        :return: Calculated CMAC
        """
        size = len(data) * 8
        prefix = bytes(12) + size.to_bytes(length=4, byteorder="big")
        return cmac(key=key, data=prefix + data)
