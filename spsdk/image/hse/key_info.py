#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for importing and handling HSE key information."""

import struct
from enum import IntEnum, IntFlag
from typing import Any, Dict, List, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKParsingError
from spsdk.image.hse.common import HseKeyBits, KeyType
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.spsdk_enum import SpsdkEnum


class HseKeyGroupOwner(IntEnum):
    """HSE Key Group owner."""

    ANY = 0  # The key are owned by ANY owner. This applies only for RAM key groups.
    CUST = 1  # The key are owned by OWNER_CUST. This applies only for NVM key groups.
    OEM = 2  # The key groups owned by OWNER_OEM. This applies only for NVM key groups.


class HseKeyFlags(IntFlag):
    """HSE Key Flags.

    The key flags specifies the operations or restrictions that can be apply to a key.
    """

    USAGE_ENCRYPT = 1  # Key is used to encrypt data
    USAGE_DECRYPT = 1 << 1  # Key is used to decrypt data
    USAGE_SIGN = 1 << 2  # Key is used to generate digital signatures or MACs
    USAGE_VERIFY = 1 << 3  # Key is used to verify digital signatures or MACs
    USAGE_EXCHANGE = 1 << 4  # Key is used for key exchange protocol (e.g. DH)
    USAGE_DERIVE = 1 << 5  # Key may be use as a base key for deriving other keys
    USAGE_KEY_PROVISION = 1 << 6  # Key used for key provisioning operation
    USAGE_AUTHORIZATION = 1 << 7  # Key can be used for system authorization
    USAGE_SMR_DECRYPT = 1 << 8  # The key is used for SMR decryption
    ACCESS_WRITE_PROT = 1 << 9  # The key is write protected and cannot change anymore
    ACCESS_DEBUG_PROT = 1 << 10  # The key is disabled when a debugger is attached
    ACCESS_EXPORTABLE = 1 << 11  # The key can be exported or not in any format
    USAGE_XTS_TWEAK = 1 << 12  # This is used as a tweak key in xts aes encryption
    USAGE_OTFAD_DECRYPT = 1 << 13  # The key is used just in OTFAD decryption

    # Mask definitions
    USAGE_MASK = (
        USAGE_ENCRYPT
        | USAGE_DECRYPT
        | USAGE_SIGN
        | USAGE_VERIFY
        | USAGE_EXCHANGE
        | USAGE_DERIVE
        | USAGE_KEY_PROVISION
        | USAGE_AUTHORIZATION
        | USAGE_SMR_DECRYPT
        | USAGE_XTS_TWEAK
        | USAGE_OTFAD_DECRYPT
    )

    ACCESS_MASK = ACCESS_WRITE_PROT | ACCESS_DEBUG_PROT | ACCESS_EXPORTABLE


class HseSmrFlags(IntFlag):
    """HSE SMR Flags.

    A set of flags that define which secure memory region (SMR),
    shall be verified before the key can be used.
    """

    SMR_0 = 1
    SMR_1 = 1 << 1
    SMR_2 = 1 << 2
    SMR_3 = 1 << 3
    SMR_4 = 1 << 4
    SMR_5 = 1 << 5
    SMR_6 = 1 << 6
    SMR_7 = 1 << 7
    SMR_8 = 1 << 8
    SMR_9 = 1 << 9
    SMR_10 = 1 << 10
    SMR_11 = 1 << 11
    SMR_12 = 1 << 12
    SMR_13 = 1 << 13
    SMR_14 = 1 << 14
    SMR_15 = 1 << 15
    SMR_16 = 1 << 16
    SMR_17 = 1 << 17
    SMR_18 = 1 << 18
    SMR_19 = 1 << 19
    SMR_20 = 1 << 20
    SMR_21 = 1 << 21
    SMR_22 = 1 << 22
    SMR_23 = 1 << 23
    SMR_24 = 1 << 24
    SMR_25 = 1 << 25
    SMR_26 = 1 << 26
    SMR_27 = 1 << 27
    SMR_28 = 1 << 28
    SMR_29 = 1 << 29
    SMR_30 = 1 << 30
    SMR_31 = 1 << 31


class HseEccCurveId(IntEnum):
    """HSE ECC Curve IDs."""

    NONE = 0
    SEC_SECP256R1 = 1
    SEC_SECP384R1 = 2
    SEC_SECP521R1 = 3
    BRAINPOOL_P256R1 = 4
    BRAINPOOL_P320R1 = 5
    BRAINPOOL_P384R1 = 6
    BRAINPOOL_P512R1 = 7
    ED25519 = 9
    CURVE25519 = 10
    ED448 = 11
    CURVE448 = 12
    USER_CURVE1 = 101
    USER_CURVE2 = 102
    USER_CURVE3 = 103


class HseAesBlockModeMask(IntFlag):
    """HSE AES Block Mode Mask.

    The values represent the cipher mode flags that an AES key can take.
    """

    BLOCK_MODE_ANY = 0  # Any block mode below
    BLOCK_MODE_XTS = 1 << 0  # XTS mode (AES)
    BLOCK_MODE_CTR = 1 << 1  # CTR mode (AES)
    BLOCK_MODE_CBC = 1 << 2  # CBC mode (AES)
    BLOCK_MODE_ECB = 1 << 3  # ECB mode (AES)
    BLOCK_MODE_CFB = 1 << 4  # CFB mode (AES)
    BLOCK_MODE_OFB = 1 << 5  # OFB mode (AES)
    BLOCK_MODE_CCM = 1 << 6  # CCM mode (AES)
    BLOCK_MODE_GCM = 1 << 7  # GCM mode (AES)


class KeyInfo(FeatureBaseClass):
    """Key Information structure.

    Contains properties of a cryptographic key including flags, bit length, counter,
    SMR flags, and key type.
    """

    FEATURE = DatabaseManager.HSE
    SUB_FEATURE = "key_import"
    FORMAT = "<HHLLBBBB"

    # Maximum key counter value
    MAX_KEY_COUNTER_VALUE = 0xFFFFFFFE

    def __init__(
        self,
        family: FamilyRevision,
        key_flags: HseKeyFlags,
        key_type: KeyType,
        smr_flags: HseSmrFlags,
        key_bit_len: HseKeyBits,
        key_counter: int = 0,
        specific_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the key information structure.

        :param key_flags: Key flags defining key properties
        :param key_bit_len: Length of the key in bits
        :param key_counter: Key counter for rollback protection
        :param smr_flags: Secure memory region flags
        :param key_type: Type of the key (HseKeyType or int value)
        :param specific_data: Specific data for the key type (e.g., ECC curve ID, RSA exponent size)
        """
        self.family = family
        self.key_flags = key_flags
        self.key_bit_len = key_bit_len
        self.key_counter = key_counter
        self.smr_flags = smr_flags
        self.key_type = key_type
        self.specific_data = specific_data or {}
        self.specific = self._encode_specific()

    def _encode_specific(self) -> bytes:
        """Encode the specific field based on key type.

        :return: Encoded specific field as bytes
        """
        # Initialize with a single byte
        specific_byte = 0

        if self.key_type in (
            KeyType.ECC_PAIR.tag,
            KeyType.ECC_PUB.tag,
            KeyType.ECC_PUB_EXT.tag,
        ):
            specific_byte = self.specific_data.get("eccCurveId", 0) & 0xFF
        elif self.key_type in (
            KeyType.RSA_PAIR.tag,
            KeyType.RSA_PUB.tag,
            KeyType.RSA_PUB_EXT.tag,
        ):
            specific_byte = self.specific_data.get("pubExponentSize", 0) & 0xFF
        elif self.key_type == KeyType.AES.tag:
            specific_byte = (
                self.specific_data.get("aesBlockModeMask", HseAesBlockModeMask(0)).value & 0xFF
            )
        return bytes([specific_byte])

    @classmethod
    def get_size(cls) -> int:
        """Get the size of the key info structure.

        :return: Size in bytes
        """
        return struct.calcsize(cls.FORMAT)

    @property
    def size(self) -> int:
        """Get the size of the key info structure.

        :return: Size in bytes
        """
        return self.get_size()

    def export(self) -> bytes:
        """Encode the key info structure to bytes.

        :return: Encoded key info as bytes
        """
        specific_byte = self._encode_specific()
        return struct.pack(
            self.FORMAT,
            int(self.key_flags),
            int(self.key_bit_len),
            self.key_counter,
            int(self.smr_flags),
            self.key_type.tag,
            specific_byte[0],
            0,
            0,
        )

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse the raw key info data into structured fields.

        :param data: Raw key info data as bytes
        :raises SPSDKParsingError: If data is missing or has invalid length
        """
        if not data:
            raise SPSDKParsingError("No data set for key info")
        if len(data) < cls.get_size():
            raise SPSDKParsingError(f"Invalid data length for key info: {len(data)}")

        (
            key_flags_int,
            key_bit_len_int,
            key_counter,
            smr_flags,
            key_type,
            specific,
            _,
            _,
        ) = struct.unpack(cls.FORMAT, data[: cls.get_size()])
        key_info = cls(
            family=family,
            key_flags=HseKeyFlags(key_flags_int),
            key_type=KeyType.from_tag(key_type),
            key_bit_len=HseKeyBits(key_bit_len_int),
            smr_flags=HseSmrFlags(smr_flags),
            key_counter=key_counter,
        )
        key_info.specific = bytes([specific])
        key_info._decode_specific()
        return key_info

    def _decode_specific(self) -> None:
        """Decode the specific field based on key type."""
        self.specific_data = {}

        if self.key_type in (
            KeyType.ECC_PAIR.tag,
            KeyType.ECC_PUB.tag,
            KeyType.ECC_PUB_EXT.tag,
        ):
            self.specific_data["eccCurveId"] = self.specific[0]

        elif self.key_type in (
            KeyType.RSA_PAIR.tag,
            KeyType.RSA_PUB.tag,
            KeyType.RSA_PUB_EXT.tag,
        ):
            self.specific_data["pubExponentSize"] = self.specific[0]

        elif self.key_type == KeyType.AES.tag:
            block_mode_mask = HseAesBlockModeMask(self.specific[0])
            self.specific_data["aesBlockModeMask"] = block_mode_mask

    def get_key_usage_flags(self) -> List[HseKeyFlags]:
        """Get the key usage flags.

        :return: List of key usage flag descriptions
        """
        flags = []
        for flag in HseKeyFlags:
            if self.key_flags & flag and flag in HseKeyFlags.USAGE_MASK:
                flags.append(flag)
        return flags

    def get_key_access_flags(self) -> List[HseKeyFlags]:
        """Get the key access flags.

        :return: List of key access flag descriptions
        """
        flags = []
        for flag in HseKeyFlags:
            if self.key_flags & flag and flag in HseKeyFlags.ACCESS_MASK:
                flags.append(flag)
        return flags

    def get_smr_flags(self) -> List[HseSmrFlags]:
        """Get the list of SMR indices that are set in the SMR flags.

        :return: List of SMR indices (0-31)
        """
        smr_flags_list = []
        for flag in HseSmrFlags:
            if self.smr_flags & flag:
                smr_flags_list.append(flag)
        return smr_flags_list

    def __str__(self) -> str:
        """Format the key info for display.

        :return: Formatted string representation
        """
        ret = "Key Information:\n"
        ret += f"Key Flags: 0x{self.key_flags:08X}\n"

        usage_flags = [flag.name or f"unknown: {flag.value}" for flag in self.get_key_usage_flags()]
        if usage_flags:
            ret += f"  Usage Flags: {','.join(usage_flags)}\n"

        access_flags = [
            flag.name or f"unknown: {flag.value}" for flag in self.get_key_access_flags()
        ]
        if access_flags:
            ret += f"  Access Flags: {', '.join(access_flags)}\n"

        ret += f"Key Bit Length: {self.key_bit_len}\n"
        ret += f"Key Counter: {self.key_counter}\n"

        smr_flags = self.get_smr_flags()
        if smr_flags:
            smr_flag_names = [flag.name or f"unknown: {flag.value}" for flag in smr_flags]
            ret += f"SMR Flags: 0x{self.smr_flags:08X} (SMRs: {', '.join(smr_flag_names)})\n"
        else:
            ret += f"SMR Flags: 0x{self.smr_flags:08X} (None)\n"

        ret += f"Key Type: {self.key_type.label} (0x{self.key_type.tag:02X})\n"

        if self.specific_data:
            ret += "Specific Data:\n"
            for key, value in self.specific_data.items():
                if isinstance(value, int):
                    ret += f"  {key}: 0x{value:X}\n"
                else:
                    ret += f"  {key}: {value}\n"

        return ret

    def __repr__(self) -> str:
        """Return a simplified string representation of the HseKeyInfo object.

        :return: String representation
        """
        # Count flags and SMRs instead of listing them
        flag_count = bin(int(self.key_flags)).count("1")
        smr_count = bin(int(self.smr_flags)).count("1")

        return f"HseKeyInfo({self.key_type.label}, {self.key_bit_len.name}, {flag_count} flags, {smr_count} SMRs)"

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load key information from a configuration file.

        :param config_file: Path to the configuration file or file-like object
        :return: HseKeyInfo instance
        :raises SPSDKValueError: If the configuration is invalid
        """
        # Extract key type
        key_type = KeyType.from_label(config.get_str("keyType"))

        # Extract key bit length
        key_bit_len = HseKeyBits(config.get_int("keyBitLen"))

        # Extract key counter
        key_counter = int(config.get_int("keyCounter", 0))

        # Extract key flags
        key_flags_list = config.get_list("keyFlags", [])
        key_flags = HseKeyFlags(0)
        for flag_str in key_flags_list:
            key_flag = HseKeyFlags[flag_str]
            key_flags |= key_flag

        # Extract SMR flags
        smr_flags_list: list[int] = config.get_list("smrFlags", [])
        smr_flags = HseSmrFlags(0)
        for flag_int in smr_flags_list:
            smr_flag = HseSmrFlags[f"SMR_{flag_int}"]
            smr_flags |= smr_flag

        # Extract specific data
        specific_data = {}
        if "specificData" in config:
            specific_config = config.get_config("specificData")

            # Handle ECC curve ID
            if "eccCurveId" in specific_config and key_type in (
                KeyType.ECC_PAIR,
                KeyType.ECC_PUB,
                KeyType.ECC_PUB_EXT,
            ):
                curve_id_str = specific_config.get_str("eccCurveId")
                specific_data["eccCurveId"] = HseEccCurveId[curve_id_str].value

            # Handle RSA public exponent size
            if "pubExponentSize" in specific_config and key_type in (
                KeyType.RSA_PAIR,
                KeyType.RSA_PUB,
                KeyType.RSA_PUB_EXT,
            ):
                exp_size = specific_config.get_int("pubExponentSize")
                specific_data["pubExponentSize"] = exp_size

            # Handle AES block mode mask
            if "aesBlockModeMask" in specific_config and key_type == KeyType.AES:
                block_modes = specific_config.get_list("aesBlockModeMask")
                block_mode_mask = 0
                for mode_str in block_modes:
                    mode = HseAesBlockModeMask[mode_str]
                    block_mode_mask |= mode
                specific_data["aesBlockModeMask"] = block_mode_mask

        return cls(
            family=FamilyRevision.load_from_config(config),
            key_flags=key_flags,
            key_bit_len=key_bit_len,
            key_counter=key_counter,
            smr_flags=smr_flags,
            key_type=key_type,
            specific_data=specific_data,
        )

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the Feature.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        config = Config(
            {
                "family": self.family.name,
                "revision": self.family.revision,
                "keyType": self.key_type.label,
                "keyBitLen": self.key_bit_len.value,
            }
        )

        # Add key counter if not zero
        if self.key_counter != 0:
            config["keyCounter"] = self.key_counter

        # Add key flags
        key_flags_list = []
        for key_flag in HseKeyFlags:
            if key_flag in [HseKeyFlags.USAGE_MASK, HseKeyFlags.ACCESS_MASK]:
                continue
            if self.key_flags & key_flag:
                key_flags_list.append(key_flag.name)
        if key_flags_list:
            config["keyFlags"] = key_flags_list

        # Add SMR flags
        smr_flags_list = self._get_smr_flags_config()
        if smr_flags_list:
            config["smrFlags"] = smr_flags_list

        # Add specific data if present
        if self.specific_data:
            specific_config: dict[str, Any] = {}

            # Handle ECC curve ID
            if "eccCurveId" in self.specific_data and self.key_type in (
                KeyType.ECC_PAIR,
                KeyType.ECC_PUB,
                KeyType.ECC_PUB_EXT,
            ):
                curve_id: int = self.specific_data["eccCurveId"]
                specific_config["eccCurveId"] = HseEccCurveId(curve_id).name

            # Handle RSA public exponent size
            if "pubExponentSize" in self.specific_data and self.key_type in (
                KeyType.RSA_PAIR,
                KeyType.RSA_PUB,
                KeyType.RSA_PUB_EXT,
            ):
                specific_config["pubExponentSize"] = self.specific_data["pubExponentSize"]

            # Handle AES block mode mask
            if "aesBlockModeMask" in self.specific_data and self.key_type == KeyType.AES:
                block_mode_mask = self.specific_data["aesBlockModeMask"]
                block_modes = []
                for mode in HseAesBlockModeMask:
                    if block_mode_mask & mode:
                        block_modes.append(mode.name)
                if block_modes:
                    specific_config["aesBlockModeMask"] = block_modes

            if specific_config:
                config["specificData"] = specific_config
        return config

    def _get_smr_flags_config(self) -> list[int]:
        """Get configuration of SMR flags."""
        smr_flags_list: list[int] = []
        for smr_flag in HseSmrFlags:
            if self.smr_flags & smr_flag:
                # Extract the SMR number from the flag name (e.g., "SMR_1" -> 1)
                assert isinstance(smr_flag.name, str)
                smr_number = int(smr_flag.name.split("_")[1])
                smr_flags_list.append(smr_number)
        return smr_flags_list

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the list of validation schemas.

        :param family: Family revision for which the validation schema should be generated.
        :return: List of validation schemas.
        """
        schemas = get_schema_file(DatabaseManager.HSE)
        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families(), family=family
        )
        return [family_schema, schemas["key_info"]]

    @classmethod
    def get_config_template(
        cls,
        family: FamilyRevision,
    ) -> str:
        """Get feature configuration template.

        :param family: The MCU family name.
        :param peripheral: Peripheral name
        :param interface: Memory interface
        :return: Template file string representation.
        """
        schemas = cls.get_validation_schemas(family)
        return cls._get_config_template(family, schemas)


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
    def parse(cls, data: bytes) -> Self:
        """Parse a key handle from bytes.

        :param data: Raw key handle value as bytes (4 bytes)
        :return: KeyHandle object
        :raises SPSDKParsingError: If data length is invalid
        """
        if len(data) != 4:
            raise SPSDKParsingError(
                f"Invalid key handle data length: {len(data)}, expected 4 bytes"
            )

        handle = int.from_bytes(data, byteorder="little")
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
        return self.handle.to_bytes(4, byteorder="little")

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


class KeyFormat(SpsdkEnum):
    """HSE Key Format (applicable for ECC keys only).

    Defines the format of ECC public keys used in HSE operations.
    """

    RAW = (0, "RAW", "Raw ECC public key: X || Y")
    UNCOMPRESSED = (1, "UNCOMPRESSED", "Standard ECC uncompressed public key: 0x04 || X || Y")
    COMPRESSED = (2, "COMPRESSED", "Standard ECC compressed public key: 0x02/0x03 || X")
