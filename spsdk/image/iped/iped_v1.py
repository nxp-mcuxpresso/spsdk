#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK IPED V1 tagged configuration structure creator.

The module serializes the IPED ELE-processed configuration structure used by
devices like i.MX943. The binary format consists of a tagged header (Tag 0x4C)
followed by region descriptors (Tag 0x43). ELE firmware reads this structure from
flash and derives IVs using AES_ECB(fuse_key, nonce || fw_version || zeros).
"""

import logging
import os
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.fuses.fuses import FuseScript
from spsdk.image.iped.prince import get_prince_cipher
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import align_block, file_extension, load_binary, value_to_int
from spsdk.utils.verifier import Verifier, VerifierResult

logger = logging.getLogger(__name__)


@dataclass
class _IpedFuseAttrs:
    """Helper object providing fuse word attributes for FuseScript generation."""

    iped_key_word0: int
    iped_key_word1: int
    iped_key_word2: int
    iped_key_word3: int


# Header and region descriptor tag constants
IPED_V1_HEADER_TAG = 0x4C
IPED_V1_REGION_TAG = 0x43
IPED_V1_REGION_SIZE = 0x20
IPED_V1_HEADER_SIZE = 0x10


@dataclass
class IpedV1DataBlob:
    """A plaintext data blob to be encrypted with IPED PRINCE cipher."""

    data_path: str
    address: int


class IpedV1Region:
    """One IPED V1 region descriptor."""

    TAG = IPED_V1_REGION_TAG
    SIZE = IPED_V1_REGION_SIZE
    ADDRESS_ALIGNMENT = 0x100

    def __init__(
        self,
        region_id: int,
        start_address: int,
        end_address: int,
        nonce: int = 0,
        address_alignment: int = ADDRESS_ALIGNMENT,
        context_key: bytes | None = None,
    ) -> None:
        """Initialize IPED V1 region descriptor.

        :param region_id: Unique region identifier (0 to 14).
        :param start_address: Start address of the IPED region.
        :param end_address: End address (first address outside the region).
        :param nonce: 64-bit nonce used by ELE for IV derivation.
        :param address_alignment: Required region address alignment.
        :param context_key: Optional 128-bit context key for offline encryption.
        :raises SPSDKValueError: If the region parameters are invalid.
        """
        self.region_id = region_id
        self.start_address = value_to_int(start_address)
        self.end_address = value_to_int(end_address)
        self.nonce = value_to_int(nonce)
        self.address_alignment = value_to_int(address_alignment)
        self.context_key = context_key
        self.validate()

    def validate(self) -> None:
        """Validate region descriptor fields.

        :raises SPSDKValueError: If the region fields are invalid.
        """
        if self.region_id < 0 or self.region_id > 0x0E:
            raise SPSDKValueError("IPED V1 region_id must be in range 0-14.")
        if self.start_address < 0 or self.start_address > 0xFFFFFFFF:
            raise SPSDKValueError("IPED V1 start_address must fit into 32 bits.")
        if self.end_address < 0 or self.end_address > 0xFFFFFFFF:
            raise SPSDKValueError("IPED V1 end_address must fit into 32 bits.")
        if self.end_address <= self.start_address:
            raise SPSDKValueError("IPED V1 region end_address must be greater than start_address.")
        if self.address_alignment <= 0:
            raise SPSDKValueError("IPED V1 address alignment must be positive.")
        if self.start_address % self.address_alignment:
            raise SPSDKValueError(
                f"IPED V1 region start_address must be aligned to "
                f"{hex(self.address_alignment)}."
            )
        if self.end_address % self.address_alignment:
            raise SPSDKValueError(
                f"IPED V1 region end_address must be aligned to " f"{hex(self.address_alignment)}."
            )
        if self.nonce < 0 or self.nonce > 0xFFFFFFFFFFFFFFFF:
            raise SPSDKValueError("IPED V1 nonce must fit into 64 bits.")

    def export(self) -> bytes:
        """Export region descriptor into the ELE configuration format.

        Format (32 bytes, little-endian 32-bit words):
          [0x00] Word0: (Tag<<24 | Length<<8 | Version) as 32-bit LE
          [0x04] Word1: (RegionID<<24) as 32-bit LE
          [0x08] Word2: Start Address as 32-bit LE
          [0x0C] Word3: End Address as 32-bit LE
          [0x10] Word4-5: Nonce as 64-bit LE
          [0x18] Reserved (8 bytes)

        :return: Serialized region descriptor bytes.
        """
        data = bytearray(self.SIZE)
        # Word 0: (Tag << 24) | (Length << 8) | Version — stored as 32-bit LE
        word0 = (self.TAG << 24) | (self.SIZE << 8) | 0x00
        data[0:4] = word0.to_bytes(4, byteorder="little")
        # Word 1: (RegionID << 24) — stored as 32-bit LE
        word1 = self.region_id << 24
        data[4:8] = word1.to_bytes(4, byteorder="little")
        # Word 2: Start Address — stored as 32-bit LE
        data[8:12] = self.start_address.to_bytes(4, byteorder="little")
        # Word 3: End Address — stored as 32-bit LE
        data[12:16] = self.end_address.to_bytes(4, byteorder="little")
        # Nonce — stored as 64-bit LE
        data[16:24] = self.nonce.to_bytes(8, byteorder="little")
        # Reserved (8 bytes, zeros)
        return bytes(data)

    @classmethod
    def parse(
        cls, data: bytes, offset: int = 0, address_alignment: int = ADDRESS_ALIGNMENT
    ) -> Self:
        """Parse region descriptor from binary data.

        :param data: Binary data containing the region descriptor.
        :param offset: Offset of the descriptor in the binary data.
        :param address_alignment: Required region address alignment.
        :raises SPSDKValueError: If the descriptor is invalid.
        :return: Parsed region descriptor.
        """
        if len(data) < offset + cls.SIZE:
            raise SPSDKValueError("IPED V1 region descriptor data is too short.")
        # Word 0: (Tag<<24 | Length<<8 | Version) as 32-bit LE
        word0 = int.from_bytes(data[offset : offset + 4], byteorder="little")
        tag = (word0 >> 24) & 0xFF
        if tag != cls.TAG:
            raise SPSDKValueError(
                f"IPED V1 region descriptor tag must be {hex(cls.TAG)}, got {hex(tag)}."
            )
        length = (word0 >> 8) & 0xFFFF
        if length != cls.SIZE:
            raise SPSDKValueError(
                f"IPED V1 region descriptor length must be {hex(cls.SIZE)}, got {hex(length)}."
            )
        # Word 1: (RegionID<<24) as 32-bit LE
        word1 = int.from_bytes(data[offset + 4 : offset + 8], byteorder="little")
        region_id = (word1 >> 24) & 0xFF
        # Word 2-3: addresses as 32-bit LE
        start_address = int.from_bytes(data[offset + 8 : offset + 12], byteorder="little")
        end_address = int.from_bytes(data[offset + 12 : offset + 16], byteorder="little")
        # Nonce as 64-bit LE
        nonce = int.from_bytes(data[offset + 16 : offset + 24], byteorder="little")
        return cls(
            region_id=region_id,
            start_address=start_address,
            end_address=end_address,
            nonce=nonce,
            address_alignment=address_alignment,
        )

    @classmethod
    def load_from_config(
        cls, config: Config, address_alignment: int, context_key: bytes | None = None
    ) -> Self:
        """Load region descriptor from configuration.

        :param config: Region configuration.
        :param address_alignment: Required region address alignment.
        :param context_key: 128-bit context key from database.
        :return: Region descriptor object.
        """
        nonce = config.get("nonce")
        if nonce is None:
            nonce_value = 0
        else:
            nonce_value = value_to_int(nonce)
        return cls(
            region_id=config.get_int("region_id"),
            start_address=config.get_int("start_address"),
            end_address=config.get_int("end_address"),
            nonce=nonce_value,
            address_alignment=address_alignment,
            context_key=context_key,
        )

    def get_config(self) -> dict[str, str | int]:
        """Get region descriptor configuration.

        :return: Configuration dictionary.
        """
        cfg: dict[str, str | int] = {
            "region_id": self.region_id,
            "start_address": hex(self.start_address),
            "end_address": hex(self.end_address),
            "nonce": hex(self.nonce),
        }
        if self.context_key is not None:
            cfg["context_key"] = "0x" + self.context_key.hex()
        return cfg


class IpedV1(FeatureBaseClass):
    """IPED V1 tagged configuration structure creator (i.MX943 and similar).

    The binary format is a tagged configuration blob processed by ELE firmware:
    - Header (16 bytes): Tag 0x4C, total length, version, FW_Version, num regions
    - Region Descriptors (32 bytes each): Tag 0x43, length, region ID, start/end
      addresses, 64-bit nonce

    ELE derives the encryption IV at runtime: IV = AES_ECB(fuse_key, nonce || fw_version || 0s)
    truncated to 64 bits. Keys reside in fuses (IPEDx_KEY0-3), not in this config.
    """

    FEATURE = DatabaseManager.IPED

    HEADER_TAG = IPED_V1_HEADER_TAG
    HEADER_SIZE = IPED_V1_HEADER_SIZE
    MAX_REGIONS = 15

    def __init__(
        self,
        family: FamilyRevision,
        regions: list[IpedV1Region] | None = None,
        fw_version: int = 0,
        version: int = 0,
        output_name: str = "iped_config",
        encrypted_name: str = "encrypted_blob",
        output_format: str = "bin",
        keyblob_address: int = 0,
        xspi_instance: str = "xspi1",
        data_blobs: list[IpedV1DataBlob] | None = None,
        user_key: bytes | None = None,
    ) -> None:
        """Initialize IPED V1 configuration structure.

        :param family: Target family.
        :param regions: List of region descriptors.
        :param fw_version: Firmware version used in IV calculation by ELE.
        :param version: Configuration structure version byte.
        :param output_name: Output file name without extension.
        :param encrypted_name: Output file name for encrypted data blobs.
        :param output_format: Output file format.
        :param keyblob_address: Absolute address where the config is placed.
        :param xspi_instance: XSPI instance name (xspi1 or xspi2) for context key selection.
        :param data_blobs: Optional list of plaintext data blobs to encrypt.
        :param user_key: Optional 128-bit user key from fuses. XORed with context_key
            from database to derive the effective PRINCE encryption key.
        :raises SPSDKValueError: If the configuration is invalid.
        """
        self.family = family
        if family.name not in [device.name for device in self.get_supported_families()]:
            raise SPSDKValueError(f"IPED is not supported for family {family}.")
        self.db = get_db(family)
        self.regions = regions[:] if regions else []
        self.fw_version = value_to_int(fw_version)
        self.version = value_to_int(version)
        self.address_alignment = self.db.get_int(self.FEATURE, "address_alignment")
        self.table_size = self.db.get_int(self.FEATURE, "table_size")
        self.output_name = output_name
        self.encrypted_name = encrypted_name
        self.output_format = output_format
        self.keyblob_address = value_to_int(keyblob_address)
        self.xspi_instance = xspi_instance
        self.data_blobs = data_blobs or []
        self.user_key = user_key
        self.validate()

    def __repr__(self) -> str:
        """Get text representation.

        :return: Text representation.
        """
        return f"IPED V1 config for {self.family}"

    def __str__(self) -> str:
        """Get text representation.

        :return: Text representation.
        """
        return self.__repr__()

    def validate(self) -> None:
        """Validate IPED V1 configuration.

        :raises SPSDKValueError: If the configuration is invalid.
        """
        if len(self.regions) < 1:
            raise SPSDKValueError("At least 1 IPED V1 region must be configured.")
        if len(self.regions) > self.MAX_REGIONS:
            raise SPSDKValueError(f"IPED V1 supports at most {self.MAX_REGIONS} regions.")
        if self.fw_version < 0 or self.fw_version > 0xFFFFFFFF:
            raise SPSDKValueError("IPED V1 fw_version must fit into 32 bits.")
        if self.version < 0 or self.version > 0xFF:
            raise SPSDKValueError("IPED V1 version must fit into 8 bits.")
        raw_size = self.HEADER_SIZE + len(self.regions) * IpedV1Region.SIZE
        if self.table_size < raw_size:
            raise SPSDKValueError(f"IPED V1 table_size must be at least {hex(raw_size)} bytes.")
        # Validate individual regions
        region_ids = set()
        for region in self.regions:
            region.validate()
            if region.region_id in region_ids:
                raise SPSDKValueError(
                    f"Duplicate region_id {region.region_id} in IPED V1 configuration."
                )
            region_ids.add(region.region_id)

    def export(self) -> bytes:
        """Export IPED V1 configuration structure into binary form.

        Format (little-endian 32-bit words):
          Header (16 bytes):
            [0x00] Word0: (Tag<<24 | TotalLength<<8 | Version) as 32-bit LE
            [0x04] Word1: FW_Version as 32-bit LE
            [0x08] Word2: (NumRegions<<24) as 32-bit LE
            [0x0C] Word3: Reserved (0)
          Region Descriptors (32 bytes each)
          Padding to table_size

        :return: Configuration structure padded to configured table size.
        """
        total_length = self.HEADER_SIZE + len(self.regions) * IpedV1Region.SIZE
        header = bytearray(self.HEADER_SIZE)
        # Word 0: (Tag<<24 | TotalLength<<8 | Version) — stored as 32-bit LE
        word0 = (self.HEADER_TAG << 24) | (total_length << 8) | (self.version & 0xFF)
        header[0:4] = word0.to_bytes(4, byteorder="little")
        # Word 1: FW_Version — stored as 32-bit LE
        header[4:8] = self.fw_version.to_bytes(4, byteorder="little")
        # Word 2: (NumRegions<<24) — stored as 32-bit LE
        word2 = len(self.regions) << 24
        header[8:12] = word2.to_bytes(4, byteorder="little")
        # Word 3: Reserved
        header[12:16] = b"\x00\x00\x00\x00"

        data = bytes(header)
        for region in self.regions:
            data += region.export()

        return align_block(data, self.table_size, padding=0)

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision | None = None) -> Self:
        """Parse IPED V1 configuration structure from bytes.

        :param data: Input binary data.
        :param family: Target family used for family-specific validation.
        :raises SPSDKValueError: If the structure is invalid or family is not provided.
        :return: Parsed IPED V1 object.
        """
        if family is None:
            raise SPSDKValueError("Family must be specified to parse IPED V1 config.")
        if len(data) < cls.HEADER_SIZE:
            raise SPSDKValueError(
                f"IPED V1 config must be at least {hex(cls.HEADER_SIZE)} bytes long."
            )
        # Word 0: (Tag<<24 | TotalLength<<8 | Version) as 32-bit LE
        word0 = int.from_bytes(data[0:4], byteorder="little")
        tag = (word0 >> 24) & 0xFF
        if tag != cls.HEADER_TAG:
            raise SPSDKValueError(
                f"IPED V1 header tag must be {hex(cls.HEADER_TAG)}, got {hex(tag)}."
            )
        total_length = (word0 >> 8) & 0xFFFF
        version = word0 & 0xFF
        # Word 1: FW_Version as 32-bit LE
        fw_version = int.from_bytes(data[4:8], byteorder="little")
        # Word 2: (NumRegions<<24) as 32-bit LE
        word2 = int.from_bytes(data[8:12], byteorder="little")
        num_regions = (word2 >> 24) & 0xFF

        expected_length = cls.HEADER_SIZE + num_regions * IpedV1Region.SIZE
        if total_length != expected_length:
            raise SPSDKValueError(
                f"IPED V1 header length {hex(total_length)} does not match "
                f"expected {hex(expected_length)} for {num_regions} regions."
            )
        if len(data) < expected_length:
            raise SPSDKValueError("IPED V1 data is too short for declared regions.")

        database = get_db(family)
        address_alignment = database.get_int(cls.FEATURE, "address_alignment")

        regions = []
        for i in range(num_regions):
            offset = cls.HEADER_SIZE + i * IpedV1Region.SIZE
            regions.append(IpedV1Region.parse(data, offset, address_alignment))

        return cls(
            family=family,
            regions=regions,
            fw_version=fw_version,
            version=version,
        )

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for IPED V1 configuration.

        :param family: Target family.
        :return: List of validation schemas.
        """
        schemas = get_schema_file(cls.FEATURE)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        sch_family["main_title"] = f"IPED V1 Configuration for {family}."
        return [sch_family, schemas["iped_v1_output"], schemas["iped_v1"]]

    @staticmethod
    def get_default_keyblob_address(family: FamilyRevision) -> int:
        """Get default absolute IPED config address for a family.

        :param family: Target family.
        :return: Default absolute address.
        """
        try:
            return (
                get_db(family)
                .device.info.memory_map.get_memory(block_name="flexspi1_ns")
                .base_address
            )
        except SPSDKError:
            return 0

    def get_config(self, data_path: str = "./") -> Config:
        """Create IPED V1 configuration.

        :param data_path: Path to store data files.
        :return: IPED V1 configuration.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["output_folder"] = data_path
        config["output_name"] = self.output_name
        config["encrypted_name"] = self.encrypted_name
        config["output_format"] = self.output_format
        config["xspi_instance"] = self.xspi_instance
        config["keyblob_address"] = hex(self.keyblob_address)
        config["fw_version"] = hex(self.fw_version)
        if self.user_key is not None:
            config["user_key"] = "0x" + self.user_key.hex()
        config["regions"] = [region.get_config() for region in self.regions]
        if self.data_blobs:
            config["data_blobs"] = [
                {"data": blob.data_path, "address": hex(blob.address)} for blob in self.data_blobs
            ]
        return config

    @classmethod
    def _get_context_keys(cls, database: Any, xspi_instance: str) -> list[bytes | None]:
        """Get context keys from the device database for the given XSPI instance.

        :param database: Device database object.
        :param xspi_instance: XSPI instance name (xspi1 or xspi2).
        :return: List of 16 context keys (128-bit each) or empty list if not available.
        """
        try:
            keys_data = database.get_list(cls.FEATURE, ["context_keys", xspi_instance])
        except (SPSDKError, KeyError):
            return []
        keys: list[bytes | None] = []
        for key_val in keys_data:
            if isinstance(key_val, int):
                keys.append(key_val.to_bytes(16, byteorder="big"))
            else:
                key_hex = str(key_val).replace("0x", "").replace("0X", "")
                keys.append(bytes.fromhex(key_hex))
        return keys

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load IPED V1 configuration from config file.

        :param config: IPED V1 configuration.
        :return: IPED V1 object.
        """
        family = FamilyRevision.load_from_config(config)
        database = get_db(family)
        address_alignment = database.get_int(cls.FEATURE, "address_alignment")
        xspi_instance = config.get_str("xspi_instance", "xspi1")
        context_keys = cls._get_context_keys(database, xspi_instance)

        regions = []
        for region_config in config.get_list_of_configs("regions"):
            region_id = region_config.get_int("region_id")
            # Auto-select context key from database based on region_id
            db_key = context_keys[region_id] if region_id < len(context_keys) else None
            region = IpedV1Region.load_from_config(region_config, address_alignment, db_key)
            regions.append(region)

        keyblob_address = config.get_int("keyblob_address", cls.get_default_keyblob_address(family))

        # Parse user_key for encryption
        user_key_str = config.get("user_key")
        user_key: bytes | None = None
        if user_key_str:
            user_key_int = value_to_int(user_key_str)
            user_key = user_key_int.to_bytes(16, byteorder="big")

        # Parse data blobs for encryption
        data_blobs: list[IpedV1DataBlob] = []
        for blob_config in config.get_list_of_configs("data_blobs", []):
            data_blobs.append(
                IpedV1DataBlob(
                    data_path=blob_config.get_input_file_name("data"),
                    address=blob_config.get_int("address"),
                )
            )

        return cls(
            family=family,
            regions=regions,
            fw_version=config.get_int("fw_version", 0),
            version=config.get_int("version", 0),
            output_name=config.get_str("output_name", "iped_config"),
            encrypted_name=config.get_str("encrypted_name", "encrypted_blob"),
            output_format=config.get_str("output_format", "bin"),
            keyblob_address=keyblob_address,
            xspi_instance=xspi_instance,
            data_blobs=data_blobs,
            user_key=user_key,
        )

    def _find_region_for_address(self, address: int) -> IpedV1Region:
        """Find the IPED region that contains the given address.

        :param address: Memory address to look up.
        :raises SPSDKValueError: If no region contains the address.
        :return: Region descriptor containing the address.
        """
        for region in self.regions:
            if region.start_address <= address < region.end_address:
                return region
        raise SPSDKValueError(
            f"No IPED region contains address {hex(address)}. "
            f"Configured regions: "
            + ", ".join(f"[{hex(r.start_address)}-{hex(r.end_address)})" for r in self.regions)
        )

    def _derive_iv(self, region: "IpedV1Region") -> int:
        """Derive the 64-bit PRINCE IV from nonce, fw_version, and user_key via AES-ECB.

        The hardware (ELE) derives the IV as:
            aes_input = nonce_msb(4B LE) + nonce_lsb(4B LE) + fw_version(4B LE) + zeros(4B)
            cipher_data = AES_ECB(key=user_key in LE byte order, data=aes_input)
            iv = int.from_bytes(cipher_data[0:8], 'little')

        :param region: Region containing the nonce value.
        :return: Derived 64-bit IV for PRINCE CTR mode.
        """
        if self.user_key is None:
            raise SPSDKValueError("user_key is required for IV derivation.")

        nonce_msb = (region.nonce >> 32) & 0xFFFFFFFF
        nonce_lsb = region.nonce & 0xFFFFFFFF

        aes_input = (
            nonce_msb.to_bytes(4, "little")
            + nonce_lsb.to_bytes(4, "little")
            + self.fw_version.to_bytes(4, "little")
            + bytes(4)
        )

        # AES key is user_key in little-endian byte order
        aes_key = bytes(reversed(self.user_key))
        aes_cipher = Cipher(algorithms.AES(aes_key), modes.ECB())
        cipher_data = aes_cipher.encryptor().update(aes_input)

        return int.from_bytes(cipher_data[0:8], "little")

    def encrypt_data(self, data: bytes, address: int) -> bytes:
        """Encrypt plaintext data using the PRINCE cipher for a given address.

        The effective key = user_key XOR context_key (from DB). The IV is derived
        from nonce + fw_version via AES-ECB keyed with user_key. Only data within
        the region boundaries is encrypted; bytes outside the region remain plaintext.

        :param data: Plaintext data to encrypt.
        :param address: Absolute memory address where the data will be placed.
        :raises SPSDKValueError: If the region has no context key or user_key is missing.
        :return: Data with the region portion encrypted.
        """
        region = self._find_region_for_address(address)
        if region.context_key is None:
            raise SPSDKValueError(
                f"Region {region.region_id} has no context key. "
                "Cannot encrypt without a context key from the database."
            )
        if self.user_key is None:
            raise SPSDKValueError(
                "user_key is required for encryption. "
                "Provide the 128-bit user key from fuses in the configuration."
            )
        # Effective key = user_key XOR context_key (same as iped-offline-tool)
        effective_key = bytes(a ^ b for a, b in zip(self.user_key, region.context_key))

        # Derive IV from nonce + fw_version via AES-ECB
        iv = self._derive_iv(region)

        # Only encrypt data within the region boundaries
        data_end = address + len(data)
        encrypt_end = min(data_end, region.end_address)
        encrypt_length = encrypt_end - address

        if encrypt_length <= 0:
            logger.warning(
                f"Data at 0x{address:x} does not overlap with region "
                f"[0x{region.start_address:x}-0x{region.end_address:x})"
            )
            return data

        if encrypt_length < len(data):
            logger.info(
                f"Data extends beyond region end (0x{region.end_address:x}). "
                f"Encrypting only first {encrypt_length} bytes of {len(data)}."
            )

        cipher = get_prince_cipher(
            key=effective_key,
            address=address,
            iv=iv,
        )
        encrypted_part = cipher.encrypt(data[:encrypt_length])
        return encrypted_part + data[encrypt_length:]

    def post_export(self, output_path: str) -> list[str]:
        """Export IPED V1 configuration and optionally encrypt data blobs.

        When data_blobs are configured, each blob is encrypted using the
        PRINCE cipher with the context key and nonce from the matching region.
        Also generates a fuse programming script for the IPED key.

        :param output_path: Output directory.
        :return: List of generated files.
        """
        os.makedirs(output_path, exist_ok=True)
        extension = file_extension(self.output_format)
        generated_files: list[str] = []

        # Export IPED table
        output_file = os.path.join(output_path, f"{self.output_name}{extension}")
        image = BinaryImage(name=self.output_name, binary=self.export(), size=self.table_size)
        image.save_binary_image(output_file, file_format=self.output_format)
        generated_files.append(output_file)

        # Encrypt data blobs if configured
        if self.data_blobs:
            encrypted_parts: list[bytes] = []
            for blob in self.data_blobs:
                plain_data = load_binary(blob.data_path)
                encrypted = self.encrypt_data(plain_data, blob.address)
                encrypted_parts.append(encrypted)
                logger.info(f"Encrypted {len(plain_data)} bytes at 0x{blob.address:x}")

            # Write concatenated encrypted blob
            encrypted_file = os.path.join(output_path, f"{self.encrypted_name}{extension}")
            encrypted_binary = b"".join(encrypted_parts)
            enc_image = BinaryImage(
                name=self.encrypted_name, binary=encrypted_binary, size=len(encrypted_binary)
            )
            enc_image.save_binary_image(encrypted_file, file_format=self.output_format)
            generated_files.append(encrypted_file)

        # Generate fuse programming script if user_key is set
        if self.user_key is not None:
            fuse_file = self._generate_fuse_script(output_path)
            if fuse_file:
                generated_files.append(fuse_file)

        return generated_files

    def _generate_fuse_script(self, output_path: str) -> str | None:
        """Generate fuse programming script for the IPED key.

        Splits the 128-bit user_key into four 32-bit fuse words and generates
        a script to program them along with IPED0_ENABLE.

        :param output_path: Output directory.
        :return: Path to generated fuse script file, or None if not available.
        """
        if self.user_key is None:
            return None

        try:
            fuse_script = FuseScript(self.family, DatabaseManager.IPED)
        except SPSDKError:
            logger.debug("No fuse definition available for IPED, skipping fuse script generation.")
            return None

        # Split 128-bit key into 32-bit words (little-endian word order)
        # KEY0 = bits[31:0], KEY1 = bits[63:32], KEY2 = bits[95:64], KEY3 = bits[127:96]
        key_int = int.from_bytes(self.user_key, "big")
        fuse_attrs = _IpedFuseAttrs(
            iped_key_word0=(key_int >> 0) & 0xFFFFFFFF,
            iped_key_word1=(key_int >> 32) & 0xFFFFFFFF,
            iped_key_word2=(key_int >> 64) & 0xFFFFFFFF,
            iped_key_word3=(key_int >> 96) & 0xFFFFFFFF,
        )

        return fuse_script.write_script("iped_fuses", output_path, fuse_attrs)

    def verify(self) -> Verifier:
        """Verify IPED V1 configuration.

        :return: Verification result.
        """
        ret = Verifier(f"IPED V1 config for {self.family}")
        try:
            self.validate()
            ret.add_record("Configuration", VerifierResult.SUCCEEDED, "Valid")
        except SPSDKError as exc:
            ret.add_record("Configuration", VerifierResult.ERROR, str(exc))
        ret.add_record_range("Regions", len(self.regions), min_val=1, max_val=self.MAX_REGIONS)
        ret.add_record("FW Version", VerifierResult.SUCCEEDED, hex(self.fw_version))
        return ret
