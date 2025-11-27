#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK Master Boot Image classes and utilities.

This module provides core classes for creating, managing, and manipulating
Master Boot Images (MBI) including manifest handling, digest computation,
CRC validation, and multiple image table management.
"""

import logging
import struct
from typing import Optional, Sequence, TypeVar

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.trustzone import TrustZone
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import Endianness, align_block

logger = logging.getLogger(__name__)


class MasterBootImageManifest:
    """MasterBootImage Manifest container for NXP MCU secure boot.

    This class represents the manifest section of a Master Boot Image (MBI) that contains
    metadata and configuration for secure boot operations. It manages firmware version,
    TrustZone settings, and provides serialization capabilities for boot image generation.

    :cvar MAGIC: Magic bytes identifier for manifest validation.
    :cvar FORMAT: Binary format string for manifest structure.
    :cvar FORMAT_VERSION: Version identifier for manifest format compatibility.
    """

    MAGIC = b"imgm"
    FORMAT = "<4s4L"
    FORMAT_VERSION = 0x0001_0000

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: Firmware version number.
        :param trust_zone: TrustZone instance for security configuration, defaults to None.
        """
        self.firmware_version = firmware_version
        self.trust_zone = trust_zone
        self.flags = 0
        self.total_length = self._calculate_length()

    def _calculate_length(self) -> int:
        """Calculate the total length of the MBI structure in bytes.

        The method computes the base structure size and adds the Trust Zone
        configuration length if it's customized.

        :return: Total length of the MBI structure in bytes.
        """
        length = struct.calcsize(self.FORMAT)
        if self.trust_zone and self.trust_zone.is_customized:
            length += len(self.trust_zone)
        return length

    def export(self) -> bytes:
        """Export MBI Manifest to binary format.

        The method serializes the MBI manifest structure including firmware version,
        total length, flags, and optional TrustZone configuration into binary data.

        :return: Exported MBI Manifest as binary data with CRC.
        """
        data = struct.pack(
            self.FORMAT,
            self.MAGIC,
            self.FORMAT_VERSION,
            self.firmware_version,
            self.total_length,
            self.flags,
        )
        if self.trust_zone and self.trust_zone.is_customized:
            data += self.trust_zone.export()
        return data

    @classmethod
    def parse(cls, family: FamilyRevision, data: bytes) -> Self:
        """Parse the binary to Master Boot Image Manifest.

        The method parses binary data containing MBI manifest information and creates
        a Master Boot Image Manifest object with firmware version and optional TrustZone
        configuration.

        :param family: Device family revision information.
        :param data: Binary data containing the MBI manifest to be parsed.
        :raises SPSDKParsingError: Invalid header is detected during parsing.
        :return: MBI Manifest object with parsed firmware version and trust zone data.
        """
        fw_version, _, extra_data = cls._parse_manifest(data)
        trust_zone = None
        if len(extra_data) > 0:
            trust_zone = TrustZone.parse(data=extra_data, family=family)
        return cls(firmware_version=fw_version, trust_zone=trust_zone)

    @classmethod
    def _verify_manifest_data(
        cls, data: bytes, magic: bytes, version: int, total_length: int
    ) -> None:
        """Verify MBI manifest data integrity and format compliance.

        Validates the manifest data by checking magic marker, format version, and data length
        to ensure the manifest conforms to expected MBI specifications.

        :param data: Raw manifest data bytes to verify.
        :param magic: Magic marker bytes from the manifest header.
        :param version: Format version number from the manifest.
        :param total_length: Expected total length of the manifest data.
        :raises SPSDKParsingError: Invalid magic marker, version mismatch, or data length error.
        """
        assert isinstance(magic, bytes)
        if magic != cls.MAGIC:
            raise SPSDKParsingError(
                "MBI Manifest: Invalid MAGIC marker detected when parsing:"
                f" {magic.hex()} != {cls.MAGIC.hex()}"
            )
        if version != cls.FORMAT_VERSION:
            raise SPSDKParsingError(
                "MBI Manifest: Invalid MANIFEST VERSION detected when parsing:"
                f" {version} != {cls.FORMAT_VERSION}"
            )
        if total_length >= len(data):
            raise SPSDKParsingError(
                "MBI Manifest: Invalid Input data length:" f" {total_length} < {len(data)}"
            )

    @classmethod
    def _parse_manifest(cls, data: bytes) -> tuple[int, Optional[EnumHashAlgorithm], bytes]:
        """Parse manifest binary data.

        The method extracts firmware version and extra data from MBI manifest binary format
        by unpacking the header structure and validating the manifest data integrity.

        :param data: Binary data containing the MBI Manifest structure.
        :raises SPSDKParsingError: Invalid header is detected during parsing.
        :return: Tuple containing firmware version, hash algorithm (always None), and extra data bytes.
        """
        (magic, version, fw_version, total_length, _) = struct.unpack(
            cls.FORMAT, data[: struct.calcsize(cls.FORMAT)]
        )
        cls._verify_manifest_data(data, magic, version, total_length)
        manifest_len = struct.calcsize(cls.FORMAT)
        extra_data = data[manifest_len:total_length]
        return fw_version, None, extra_data


class MasterBootImageManifestDigest(MasterBootImageManifest):
    """MasterBootImage Manifest with digest hash algorithm support.

    This class extends the basic MBI manifest to include cryptographic hash
    algorithm information and digest validation capabilities. It manages
    hash algorithm selection, flag calculation, and provides utilities
    for hash size determination.

    :cvar DIGEST_PRESENT_FLAG: Flag indicating digest presence in manifest.
    :cvar HASH_TYPE_MASK: Mask for extracting hash type from flags.
    :cvar SUPPORTED_ALGORITHMS: List of supported hash algorithms.
    """

    DIGEST_PRESENT_FLAG = 0x8000_0000
    HASH_TYPE_MASK = 0x0F
    SUPPORTED_ALGORITHMS = [
        EnumHashAlgorithm.SHA256,
        EnumHashAlgorithm.SHA384,
        EnumHashAlgorithm.SHA512,
    ]

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone] = None,
        digest_hash_algo: Optional[EnumHashAlgorithm] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: Firmware version number.
        :param trust_zone: TrustZone instance for security configuration, defaults to None.
        :param digest_hash_algo: Digest hash algorithm to use, defaults to None.
        :raises SPSDKValueError: Unsupported digest hash algorithm provided.
        """
        super().__init__(firmware_version, trust_zone)
        if digest_hash_algo and digest_hash_algo not in self.SUPPORTED_ALGORITHMS:
            raise SPSDKValueError(f"Unsupported digest hash algorithm: {digest_hash_algo}")
        self.digest_hash_algo = digest_hash_algo
        self.flags = self._calculate_flags()
        self.total_length = self._calculate_length()

    def _calculate_flags(self) -> int:
        """Calculate flags value based on digest hash algorithm.

        The method determines the appropriate flags by combining the digest present flag
        with the hash algorithm type identifier when a digest hash algorithm is configured.

        :return: Calculated flags value, 0 if no digest hash algorithm is set.
        """
        if not self.digest_hash_algo:
            return 0
        hash_algo_types = {
            None: 0,
            EnumHashAlgorithm.SHA256: 1,
            EnumHashAlgorithm.SHA384: 2,
            EnumHashAlgorithm.SHA512: 3,
        }
        return self.DIGEST_PRESENT_FLAG | hash_algo_types[self.digest_hash_algo]

    @staticmethod
    def get_hash_size(algorithm: EnumHashAlgorithm) -> int:
        """Get hash size by used algorithm.

        :param algorithm: Hash algorithm to get size for.
        :return: Hash size in bytes, or 0 if algorithm is not supported.
        """
        return {
            EnumHashAlgorithm.SHA256: 32,
            EnumHashAlgorithm.SHA384: 48,
            EnumHashAlgorithm.SHA512: 64,
        }.get(algorithm, 0)

    @classmethod
    def parse(cls, family: FamilyRevision, data: bytes) -> Self:
        """Parse the binary to Master Boot Image Manifest.

        :param family: Device family.
        :param data: Binary Image with MBI Manifest.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: MBI Manifest object.
        """
        fw_version, hash_algo, extra_data = cls._parse_manifest(data)
        trust_zone = None
        if len(extra_data) > 0:
            trust_zone = TrustZone.parse(data=extra_data, family=family)
        return cls(firmware_version=fw_version, trust_zone=trust_zone, digest_hash_algo=hash_algo)

    @classmethod
    def _parse_manifest(cls, data: bytes) -> tuple[int, Optional[EnumHashAlgorithm], bytes]:
        """Parse manifest binary data.

        The method extracts firmware version, hash algorithm type, and extra data
        from the MBI manifest binary structure.

        :param data: Binary data with MBI Manifest.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: Tuple with fw version, hash type and image extra data.
        """
        (magic, version, fw_version, total_length, flags) = struct.unpack(
            cls.FORMAT, data[: struct.calcsize(cls.FORMAT)]
        )
        cls._verify_manifest_data(data, magic, version, total_length)
        hash_algo: Optional[EnumHashAlgorithm] = None
        if flags & cls.DIGEST_PRESENT_FLAG:
            hash_algo = {
                0: None,
                1: EnumHashAlgorithm.SHA256,
                2: EnumHashAlgorithm.SHA384,
                3: EnumHashAlgorithm.SHA512,
            }[flags & cls.HASH_TYPE_MASK]
        manifest_len = struct.calcsize(cls.FORMAT)
        extra_data = data[manifest_len:total_length]
        return fw_version, hash_algo, extra_data


class MasterBootImageManifestCrc(MasterBootImageManifest):
    """Master Boot Image Manifest with CRC validation.

    This class extends the base MasterBootImageManifest to include CRC (Cyclic Redundancy Check)
    functionality for data integrity verification. It manages manifest data with embedded CRC
    values for secure boot operations in NXP MCU devices.
    """

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: Firmware version number.
        :param trust_zone: TrustZone instance for security configuration, defaults to None.
        """
        super().__init__(firmware_version, trust_zone)
        self.crc = 0

    def export(self) -> bytes:
        """Export MBI Manifest to binary format.

        The method exports the MBI manifest data by calling the parent class export method
        and appending the CRC value as a 4-byte little-endian unsigned integer.

        :return: Exported binary data of MBI Manifest with appended CRC checksum.
        """
        data = super().export()
        data += struct.pack("<L", self.crc)
        return data

    @classmethod
    def parse(cls, family: FamilyRevision, data: bytes) -> Self:
        """Parse the binary to Master Boot Image Manifest.

        The method parses binary data containing MBI manifest, extracts firmware version,
        CRC, and optional TrustZone configuration to create a complete MBI manifest object.

        :param family: Device family revision information.
        :param data: Binary data containing the MBI manifest structure.
        :raises SPSDKParsingError: Invalid header is detected or insufficient data for CRC.
        :return: MBI Manifest object with parsed configuration.
        """
        fw_version, _, extra_data = cls._parse_manifest(data)
        if len(extra_data) < 4:
            raise SPSDKParsingError("Extra data must contain crc.")

        crc = int.from_bytes(extra_data[-4:], Endianness.LITTLE.value)
        trust_zone = None
        if extra_data[:-4]:
            trust_zone = TrustZone.parse(data=extra_data[:-4], family=family)
        mcx_manifest = cls(firmware_version=fw_version, trust_zone=trust_zone)
        mcx_manifest.crc = crc
        return mcx_manifest

    def _calculate_length(self) -> int:
        """Calculate the total length of this MBI object including its specific data.

        This method extends the parent class length calculation by adding 4 bytes
        for this object's specific data fields.

        :return: Total length in bytes including parent object length plus 4 additional bytes.
        """
        return super()._calculate_length() + 4

    def compute_crc(self, image: bytes) -> None:
        """Compute and add CRC field.

        The method calculates CRC32 MPEG checksum for the provided image data and stores
        the result in the crc attribute.

        :param image: Image data to be used to compute CRC checksum.
        """
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        self.crc = crc_obj.calculate(image)


T_Manifest = TypeVar(
    "T_Manifest", MasterBootImageManifest, MasterBootImageManifestDigest, MasterBootImageManifestCrc
)


class MultipleImageEntry:
    """Multiple Image Entry for relocation table operations.

    Represents an entry in a relocation table that contains binary image data
    and associated metadata for memory relocation operations. Each entry manages
    the source and destination addresses along with control flags for the
    relocation process.

    :cvar LTI_LOAD: Flag to copy load segment into target memory.
    """

    # flag to simply copy load segment into target memory
    LTI_LOAD = 1 << 0

    def __init__(self, img: bytes, dst_addr: int, flags: int = LTI_LOAD):
        """Initialize Multiple Image Entry (LTI) section with binary data and configuration.

        Creates a new LTI section that defines how binary image data should be loaded
        to a specific destination address in memory during boot process.

        :param img: Binary image data to be loaded.
        :param dst_addr: Destination address where the image will be loaded (0x0 to 0xFFFFFFFF).
        :param flags: Load flags, currently only LTI_LOAD is supported.
        :raises SPSDKError: If destination address is out of valid range.
        :raises SPSDKError: If unsupported flags are specified (only LTI_LOAD supported).
        """
        if dst_addr < 0 or dst_addr > 0xFFFFFFFF:
            raise SPSDKError("Invalid destination address")
        if flags != self.LTI_LOAD:
            raise SPSDKError("For now, other section types than LTI_LOAD, are not supported")
        self._img = img
        self._src_addr = 0
        self._dst_addr = dst_addr
        self._flags = flags

    @property
    def image(self) -> bytes:
        """Get binary image data.

        :return: The binary image data as bytes.
        """
        return self._img

    @property
    def src_addr(self) -> int:
        """Get the source address of the MBI image.

        This value is calculated automatically when building the image and represents
        the memory location where the image data will be loaded.

        :return: Source address as integer value.
        """
        return self._src_addr

    @src_addr.setter
    def src_addr(self, value: int) -> None:
        """Set the source address value.

        :param value: Source address to be set.
        """
        self._src_addr = value

    @property
    def dst_addr(self) -> int:
        """Get destination address.

        :return: Destination address value.
        """
        return self._dst_addr

    @property
    def size(self) -> int:
        """Size of the image (not aligned).

        :return: Size of the image in bytes without any alignment padding.
        """
        return len(self.image)

    @property
    def flags(self) -> int:
        """Get flags value.

        Flags property that returns the current flags value, which is currently not used
        in the implementation.

        :return: The flags value as integer.
        """
        return self._flags

    @property
    def is_load(self) -> bool:
        """Check if entry represents a LOAD section.

        :return: True if the entry represents a LOAD section, False otherwise.
        """
        return (self.flags & self.LTI_LOAD) != 0

    def export_entry(self) -> bytes:
        """Export relocation table entry in binary form.

        Converts the relocation table entry into a packed binary representation using
        little-endian format. The binary data contains source address, destination address,
        size, and flags in sequential order.

        :return: Binary representation of the relocation table entry (16 bytes total).
        """
        result = bytes()
        result += struct.pack("<I", self.src_addr)  # source address
        result += struct.pack("<I", self.dst_addr)  # dest address
        result += struct.pack("<I", self.size)  # length
        result += struct.pack("<I", self.flags)  # flags
        return result

    @staticmethod
    def parse(data: bytes) -> "MultipleImageEntry":
        """Parse multiple image entry from binary data.

        Extracts image data, destination address, and flags from the binary representation
        of a relocation table entry in the Multiple Image Boot format.

        :param data: Binary data containing the relocation table entry and image data.
        :raises SPSDKParsingError: When the image size exceeds the available data length.
        :return: Parsed multiple image entry object with extracted image data and metadata.
        """
        (src_addr, dst_addr, size, flags) = struct.unpack("<4I", data[: 4 * 4])
        if src_addr + size > len(data):
            raise SPSDKParsingError("The image doesn't fit into given data")

        return MultipleImageEntry(data[src_addr : src_addr + size], dst_addr, flags)

    def export_image(self) -> bytes:
        """Export binary image data aligned to 4-byte boundary.

        The method takes the current image data and ensures it's properly aligned to 4-byte boundaries,
        which is typically required for proper memory alignment in embedded systems.

        :return: Image data as bytes aligned to 4-byte boundary.
        """
        return align_block(self.image, 4)


class MultipleImageTable:
    """Multiple Image Table for merging and relocating multiple images.

    This class manages the creation and export of a relocation table that allows
    merging several images into a single image. It supports multicore applications
    where each core has its own image, and TrustZone applications that combine
    secure and non-secure images.
    """

    def __init__(self) -> None:
        """Initialize the Multiple Image Table.

        Creates a new instance with an empty list of entries and sets the start address to 0.
        """
        self._entries: list[MultipleImageEntry] = []
        self.start_address = 0

    @property
    def header_version(self) -> int:
        """Get format version of the structure for the header.

        :return: Format version number, always returns 0.
        """
        return 0

    @property
    def entries(self) -> Sequence[MultipleImageEntry]:
        """Get list of all multiple image entries.

        :return: Sequence of all multiple image entries in the container.
        """
        return self._entries

    def add_entry(self, entry: MultipleImageEntry) -> None:
        """Add entry into relocation table.

        :param entry: Multiple image entry to add to the relocation table.
        """
        self._entries.append(entry)

    def reloc_table(self, start_addr: int) -> bytes:
        """Export relocation table in binary format.

        Generates a binary representation of the relocation table including all entries
        and the table header with metadata.

        :param start_addr: Start address of the relocation table in memory.
        :return: Binary data containing the complete relocation table.
        """
        result = bytes()
        # export relocation entries table
        for entry in self.entries:
            result += entry.export_entry()
        # export relocation table header
        result += struct.pack("<I", 0x4C54424C)  # header marker
        result += struct.pack("<I", self.header_version)  # version
        result += struct.pack("<I", len(self._entries))  # number of entries
        result += struct.pack("<I", start_addr)  # pointer to entries
        return result

    def export(self, start_addr: int) -> bytes:
        """Export MBI entries with relocation table to binary format.

        This method processes all loadable entries in the MBI, assigns source addresses
        starting from the specified start address, and exports them as a continuous
        binary blob followed by a relocation table.

        :param start_addr: Start address where the images are exported; the value
                          matches source address for the first image.
        :return: Binary data containing all exported images followed by relocation table.
        :raises SPSDKError: If there is no entry for export.
        """
        if not self._entries:
            raise SPSDKError("There must be at least one entry for export")
        self.start_address = start_addr
        src_addr = start_addr
        result = bytes()
        for entry in self.entries:
            if entry.is_load:
                entry.src_addr = src_addr
                entry_img = entry.export_image()
                result += entry_img
                src_addr += len(entry_img)
        result += self.reloc_table(start_addr + len(result))
        return result

    @staticmethod
    def parse(data: bytes) -> Optional["MultipleImageTable"]:
        """Parse binary data to get the Multiple Image Table.

        The method extracts the multiple application table from binary data by parsing
        the header information and creating table entries for each detected application.

        :param data: Binary data containing the multiple image table structure.
        :raises SPSDKParsingError: The application table parsing fails.
        :return: Multiple Image Table instance if valid table detected, None otherwise.
        """
        (marker, header_version, n_entries, start_address) = struct.unpack(
            "<4I", data[-struct.calcsize("<4I") :]
        )
        if marker != 0x4C54424C or header_version != MultipleImageTable().header_version:
            return None

        app_table = MultipleImageTable()
        app_table.start_address = start_address
        for n in range(n_entries):
            app_table.add_entry(MultipleImageEntry.parse(data[: -16 * (1 + n)]))

        return app_table
