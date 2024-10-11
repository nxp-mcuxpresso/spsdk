#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Master Boot Image."""

import logging
import struct
from typing import Optional, Sequence, TypeVar

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.exceptions import SPSDKError, SPSDKParsingError, SPSDKValueError
from spsdk.image.trustzone import TrustZone
from spsdk.utils.misc import Endianness, align_block

logger = logging.getLogger(__name__)


class MasterBootImageManifest:
    """MasterBootImage Manifest."""

    MAGIC = b"imgm"
    FORMAT = "<4s4L"
    FORMAT_VERSION = 0x0001_0000

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: firmware version
        :param trust_zone: TrustZone instance, defaults to None
        """
        self.firmware_version = firmware_version
        self.trust_zone = trust_zone
        self.flags = 0
        self.total_length = self._calculate_length()

    def _calculate_length(self) -> int:
        length = struct.calcsize(self.FORMAT)
        if self.trust_zone:
            length += len(self.trust_zone.export())
        return length

    def export(self) -> bytes:
        """Serialize MBI Manifest."""
        data = struct.pack(
            self.FORMAT,
            self.MAGIC,
            self.FORMAT_VERSION,
            self.firmware_version,
            self.total_length,
            self.flags,
        )
        if self.trust_zone:
            data += self.trust_zone.export()
        return data

    @classmethod
    def parse(cls, family: str, data: bytes, revision: str = "latest") -> Self:
        """Parse the binary to Master Boot Image Manifest.

        :param family: Device family.
        :param data: Binary Image with MBI Manifest.
        :param revision: Optional chip family revision.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: MBI Manifest object
        """
        fw_version, _, extra_data = cls._parse_manifest(data)
        trust_zone = None
        if len(extra_data) > 0:
            trust_zone = TrustZone.from_binary(
                family=family, raw_data=extra_data, revision=revision
            )
        return cls(firmware_version=fw_version, trust_zone=trust_zone)

    @classmethod
    def _verify_manifest_data(
        cls, data: bytes, magic: bytes, version: int, total_length: int
    ) -> None:
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

        :param data: Binary data with MBI Manifest.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: Tuple with fw version and image extra data
        """
        (magic, version, fw_version, total_length, _) = struct.unpack(
            cls.FORMAT, data[: struct.calcsize(cls.FORMAT)]
        )
        cls._verify_manifest_data(data, magic, version, total_length)
        manifest_len = struct.calcsize(cls.FORMAT)
        extra_data = data[manifest_len:total_length]
        return fw_version, None, extra_data


class MasterBootImageManifestDigest(MasterBootImageManifest):
    """MasterBootImage Manifest with information about hash algorithm."""

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

        :param firmware_version: firmware version
        :param digest_hash_algo: Digest hash algorithm, defaults to None
        :param trust_zone: TrustZone instance, defaults to None
        """
        super().__init__(firmware_version, trust_zone)
        if digest_hash_algo and digest_hash_algo not in self.SUPPORTED_ALGORITHMS:
            raise SPSDKValueError(f"Unsupported digest hash algorithm: {digest_hash_algo}")
        self.digest_hash_algo = digest_hash_algo
        self.flags = self._calculate_flags()
        self.total_length = self._calculate_length()

    def _calculate_flags(self) -> int:
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
        """Get hash size by used algorithm."""
        return {
            EnumHashAlgorithm.SHA256: 32,
            EnumHashAlgorithm.SHA384: 48,
            EnumHashAlgorithm.SHA512: 64,
        }.get(algorithm, 0)

    @classmethod
    def parse(cls, family: str, data: bytes, revision: str = "latest") -> Self:
        """Parse the binary to Master Boot Image Manifest.

        :param family: Device family.
        :param data: Binary Image with MBI Manifest.
        :param revision: Optional chip family revision.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: MBI Manifest object
        """
        fw_version, hash_algo, extra_data = cls._parse_manifest(data)
        trust_zone = None
        if len(extra_data) > 0:
            trust_zone = TrustZone.from_binary(
                family=family, raw_data=extra_data, revision=revision
            )
        return cls(firmware_version=fw_version, trust_zone=trust_zone, digest_hash_algo=hash_algo)

    @classmethod
    def _parse_manifest(cls, data: bytes) -> tuple[int, Optional[EnumHashAlgorithm], bytes]:
        """Parse manifest binary data.

        :param data: Binary data with MBI Manifest.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: Tuple with fw version, hash type and image extra data
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
    """MasterBootImage Manifest with CRC."""

    def __init__(
        self,
        firmware_version: int,
        trust_zone: Optional[TrustZone] = None,
    ) -> None:
        """Initialize MBI Manifest object.

        :param firmware_version: firmware version
        :param digest_hash_algo: Digest hash algorithm, defaults to None
        :param trust_zone: TrustZone instance, defaults to None
        """
        super().__init__(firmware_version, trust_zone)
        self.crc = 0

    def export(self) -> bytes:
        """Serialize MBI Manifest."""
        data = super().export()
        data += struct.pack("<L", self.crc)
        return data

    @classmethod
    def parse(cls, family: str, data: bytes, revision: str = "latest") -> Self:
        """Parse the binary to Master Boot Image Manifest.

        :param family: Device family.
        :param data: Binary Image with MBI Manifest.
        :param revision: Optional chip family revision.
        :raises SPSDKParsingError: Invalid header is detected.
        :return: MBI Manifest object
        """
        fw_version, _, extra_data = cls._parse_manifest(data)
        if len(extra_data) < 4:
            raise SPSDKParsingError("Extra data must contain crc.")

        crc = int.from_bytes(extra_data[-4:], Endianness.LITTLE.value)
        trust_zone = None
        if extra_data[:-4]:
            trust_zone = TrustZone.from_binary(
                family=family, raw_data=extra_data[:-4], revision=revision
            )
        mcx_manifest = cls(firmware_version=fw_version, trust_zone=trust_zone)
        mcx_manifest.crc = crc
        return mcx_manifest

    def _calculate_length(self) -> int:
        return super()._calculate_length() + 4

    def compute_crc(self, image: bytes) -> None:
        """Compute and add CRC field.

        :param image: Image data to be used to compute CRC
        """
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        self.crc = crc_obj.calculate(image)


T_Manifest = TypeVar(
    "T_Manifest", MasterBootImageManifest, MasterBootImageManifestDigest, MasterBootImageManifestCrc
)


class MultipleImageEntry:
    """The class represents an entry in relocation table.

    It also contains a corresponding image (binary)
    """

    # flag to simply copy load segment into target memory
    LTI_LOAD = 1 << 0

    def __init__(self, img: bytes, dst_addr: int, flags: int = LTI_LOAD):
        """Constructor.

        :param img: binary image data
        :param dst_addr: destination address
        :param flags: see LTI constants
        :raises SPSDKError: If invalid destination address
        :raises SPSDKError: Other section types (INIT) are not supported
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
        """Binary image data."""
        return self._img

    @property
    def src_addr(self) -> int:
        """Source address; this value is calculated automatically when building the image."""
        return self._src_addr

    @src_addr.setter
    def src_addr(self, value: int) -> None:
        """Setter.

        :param value: to set
        """
        self._src_addr = value

    @property
    def dst_addr(self) -> int:
        """Destination address."""
        return self._dst_addr

    @property
    def size(self) -> int:
        """Size of the image (not aligned)."""
        return len(self.image)

    @property
    def flags(self) -> int:
        """Flags, currently not used."""
        return self._flags

    @property
    def is_load(self) -> bool:
        """True if entry represents LOAD section."""
        return (self.flags & self.LTI_LOAD) != 0

    def export_entry(self) -> bytes:
        """Export relocation table entry in binary form."""
        result = bytes()
        result += struct.pack("<I", self.src_addr)  # source address
        result += struct.pack("<I", self.dst_addr)  # dest address
        result += struct.pack("<I", self.size)  # length
        result += struct.pack("<I", self.flags)  # flags
        return result

    @staticmethod
    def parse(data: bytes) -> "MultipleImageEntry":
        """Parse relocation table entry from binary form."""
        (src_addr, dst_addr, size, flags) = struct.unpack("<4I", data[: 4 * 4])
        if src_addr + size > len(data):
            raise SPSDKParsingError("The image doesn't fit into given data")

        return MultipleImageEntry(data[src_addr : src_addr + size], dst_addr, flags)

    def export_image(self) -> bytes:
        """Binary image aligned to the 4-bytes boundary."""
        return align_block(self.image, 4)


class MultipleImageTable:
    """The class allows to merge several images into single image and add relocation table.

    It can be used for multicore images (one image for each core)
    or trustzone images (merging secure and non-secure image)
    """

    def __init__(self) -> None:
        """Initialize the Multiple Image Table."""
        self._entries: list[MultipleImageEntry] = []
        self.start_address = 0

    @property
    def header_version(self) -> int:
        """Format version of the structure for the header."""
        return 0

    @property
    def entries(self) -> Sequence[MultipleImageEntry]:
        """List of all entries."""
        return self._entries

    def add_entry(self, entry: MultipleImageEntry) -> None:
        """Add entry into relocation table.

        :param entry: to add
        """
        self._entries.append(entry)

    def reloc_table(self, start_addr: int) -> bytes:
        """Relocate table.

        :param start_addr: start address of the relocation table
        :return: export relocation table in binary form
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
        """Export.

        :param start_addr: start address where the images are exported;
                        the value matches source address for the first image
        :return: images with relocation table
        :raises SPSDKError: If there is no entry for export
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
        """Parse binary to get the Multiple application table.

        :param data: Data bytes where the application is looked for
        :raises SPSDKParsingError: The application table parsing fails.

        :return: Multiple application table if detected.
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
