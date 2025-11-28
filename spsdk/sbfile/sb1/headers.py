#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Secure Binary v1 header structures and utilities.

This module provides classes for handling Secure Binary version 1 headers,
including boot flags, main boot headers, section headers, and boot section
headers used in SB1 file format processing.
"""

from datetime import datetime
from struct import calcsize, pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import (
    BcdVersion3,
    BcdVersion3Format,
    SecBootBlckSize,
    pack_timestamp,
    unpack_timestamp,
)
from spsdk.sbfile.sb2.commands import BaseClass, CmdHeader, CmdTag
from spsdk.utils.misc import swap16
from spsdk.utils.spsdk_enum import SpsdkEnum


class SecureBootFlagsV1(SpsdkEnum):
    """Secure Binary flags enumeration for SB1 format section headers.

    This enumeration defines the available flags that can be applied to sections
    in Secure Binary version 1 format, controlling section behavior such as
    bootability and encryption settings.
    """

    NONE = (0, "NONE", "No flags")
    ROM_SECTION_BOOTABLE = (
        1,
        "ROM_SECTION_BOOTABLE",
        "The section is bootable and contains a sequence of bootloader commands.",
    )
    ROM_SECTION_CLEARTEXT = (
        2,
        "ROM_SECTION_CLEARTEXT",
        "The section is unencrypted. Applies only if the rest of the boot image is encrypted.",
    )


########################################################################################################################
# Secure Binary Header Class (Version SB1.x)
########################################################################################################################
# pylint: disable=too-many-instance-attributes
class SecureBootHeaderV1(BaseClass):
    """Secure Binary Header V1.

    This class represents and manages the header structure for Secure Binary version 1 format
    used in NXP MCU boot images. It handles the binary format, validation, and serialization
    of boot image headers including version information, security flags, and cryptographic
    digests.

    :cvar _SIGNATURE1: Binary signature 'STMP' for header identification.
    :cvar _SIGNATURE2: Binary signature 'sgtl' for header identification.
    """

    # binary format of the header
    _FORMAT = "<20s4s2BH3I5H2s4sQ13H6s"
    # size of the header in bytes
    _SIZE = calcsize(_FORMAT)
    # binary signature 1 for header identification
    _SIGNATURE1 = b"STMP"
    # binary signature 2 for header identification
    _SIGNATURE2 = b"sgtl"

    def __init__(
        self,
        version: str = "1.0",
        product_version: BcdVersion3Format = BcdVersion3.DEFAULT,
        component_version: BcdVersion3Format = BcdVersion3.DEFAULT,
        flags: int = 0,
        drive_tag: int = 0,
        digest: bytes = b"\0" * 20,
        timestamp: Optional[datetime] = None,
    ) -> None:
        """Initialize SecureBootHeaderV1.

        Creates a new instance of SecureBootHeaderV1 with the specified parameters for secure boot
        image generation.

        :param version: Boot image format version, must be "1.0", "1.1", or "1.2".
        :param product_version: Product version in BCD format.
        :param component_version: Component version in BCD format.
        :param flags: Flags associated with the entire image.
        :param drive_tag: Identifier for the disk drive or partition containing this image.
        :param digest: SHA-1 digest of header fields (20 bytes). First 16 bytes serve as CBC
            initialization vector.
        :param timestamp: Creation timestamp. Use None for current time. Fixed values should only
            be used for regression testing.
        :raises SPSDKError: Invalid header version provided.
        """
        # SHA-1 digest of all fields of the header prior to this one.
        self.digest = digest
        # Major version of the boot image format, currently 1. Minor version of the boot image format, currently 1 or 2.
        if version not in ("1.0", "1.1", "1.2"):
            raise SPSDKError("Invalid header version")
        self.version = version
        self.flags = flags
        # Size of the entire image in blocks.
        self.image_blocks = 0
        # Unique identifier of the section to start booting from.
        self.first_boot_section_id = 0
        # Number of entries in the DEK dictionary.
        self.key_count = 0
        # Size of the entire image header in blocks. This seems to be a constant.
        self.header_blocks = SecBootBlckSize.to_num_blocks(self._SIZE)
        # Number of sections.
        self.section_count = 0
        # Size in blocks of a section header. This seems to be a constant.
        self.section_header_size = SecBootBlckSize.to_num_blocks(BootSectionHeaderV1.SIZE)
        # Timestamp in microseconds size 1-1-2000 00:00 when the image was created.
        self.timestamp = (
            timestamp if timestamp else datetime.fromtimestamp(int(datetime.now().timestamp()))
        )
        # Product version in format #.#.#
        self.product_version: BcdVersion3 = BcdVersion3.to_version(product_version)
        # Component version in format #.#.#
        self.component_version: BcdVersion3 = BcdVersion3.to_version(component_version)
        # Identifier for the disk drive or partition containing this image.
        self.drive_tag = drive_tag

    @property
    def key_dictionary_block(self) -> int:
        """Get the key dictionary block offset.

        Calculates the offset to the key dictionary block by adding the header blocks
        and the total size of all section headers.

        :return: Offset to the key dictionary block in bytes.
        """
        return self.header_blocks + self.section_count * self.section_header_size

    @property
    def first_boot_tag_block(self) -> int:
        """Get the first boot tag block index.

        Calculates the position of the first boot tag block based on the key dictionary
        block position and the number of keys present.

        :return: Index of the first boot tag block.
        """
        return self.key_dictionary_block + self.key_count * 2

    @property
    def size(self) -> int:
        """Return size of the header in bytes.

        :return: Size of the header in bytes.
        """
        return self._SIZE

    def __repr__(self) -> str:
        """Return string representation of the header object.

        The representation includes the version number and image blocks information
        in a human-readable format.

        :return: String representation containing version and image blocks.
        """
        return f"Header: v{self.version}, {self.image_blocks}"

    def __str__(self) -> str:
        """Get string representation of the SB1 header.

        Provides a formatted string containing all header fields including digest, version,
        flags, block information, timestamps, and other metadata for debugging and logging
        purposes.

        :return: Formatted string with header information.
        """
        return (
            f" Digest:               {self.digest.hex()}\n"
            f" Version:              {self.version}\n"
            f" Flags:                0x{self.flags:04X}\n"
            f" Image Blocks:         {self.image_blocks}\n"
            f" First Boot Tag Block: {self.first_boot_tag_block}\n"
            f" First Boot SectionID: {self.first_boot_section_id}\n"
            f" Key Count:            {self.key_count}\n"
            f" Key Dictionary Block: {self.key_dictionary_block}\n"
            f" Header Blocks:        {self.header_blocks}\n"
            f" Section Count:        {self.section_count}\n"
            f" Section Header Size:  {self.section_header_size}\n"
            f" Timestamp:            {self.timestamp}\n"
            f" Product Version:      {self.product_version}\n"
            f" Component Version:    {self.component_version}\n"
            f" Drive Tag:            {self.drive_tag}\n"
        )

    def export(
        self,
        padding8: Optional[bytes] = None,
    ) -> bytes:
        """Export header to binary format.

        Serializes the header object into its binary representation with proper formatting
        and padding. The digest is calculated and prepended to the final result.

        :param padding8: Optional 8-byte padding for header, uses random bytes if None.
            Should only be specified for regression testing to ensure reproducible results.
        :return: Binary representation of the header with digest prepended.
        """
        major_version, minor_version = [int(v) for v in self.version.split(".")]
        product_version_words = [swap16(n) for n in self.product_version.nums]
        component_version_words = [swap16(n) for n in self.component_version.nums]
        signature2 = random_bytes(4)
        padding = padding8 if padding8 else random_bytes(8)

        if (major_version > 1) or ((major_version == 1) and (minor_version >= 2)):
            signature2 = self._SIGNATURE2

        result = pack(
            self._FORMAT,
            self.digest,
            self._SIGNATURE1,
            # header version
            major_version,
            minor_version,
            self.flags,
            self.image_blocks,
            self.first_boot_tag_block,
            self.first_boot_section_id,
            self.key_count,
            self.key_dictionary_block,
            self.header_blocks,
            self.section_count,
            self.section_header_size,
            padding[0:2],
            signature2,
            pack_timestamp(self.timestamp),
            # product version
            product_version_words[0],
            0,
            product_version_words[1],
            0,
            product_version_words[2],
            0,
            # component version
            component_version_words[0],
            0,
            component_version_words[1],
            0,
            component_version_words[2],
            0,
            self.drive_tag,
            padding[2:],
        )

        result = result[len(self.digest) :]
        self.digest = get_hash(result, EnumHashAlgorithm.SHA1)

        return self.digest + result

    # pylint: disable=too-many-locals
    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into SecureBootHeaderV1 instance.

        Deserializes binary data containing a secure boot header version 1 into a structured
        object. The method validates header signatures and version compatibility during parsing.

        :param data: Binary data to be decoded into header instance.
        :return: Parsed secure boot header v1 instance.
        :raises SPSDKError: Insufficient data size for header parsing.
        :raises SPSDKError: Invalid or unexpected header signature found.
        """
        if SecureBootHeaderV1._SIZE > len(data):
            raise SPSDKError("Insufficient size")

        (
            digest,
            signature1,
            # header version
            major_version,
            minor_version,
            flags,
            image_blocks,
            _first_boot_tag_block,
            first_boot_section_id,
            key_count,
            _key_dictionary_block,
            header_blocks,
            section_count,
            section_header_size,
            _,  # padding 2
            signature2,
            timestamp,
            pv0,
            _,
            pv1,
            _,
            pv2,
            _,  # product version
            cv0,
            _,
            cv1,
            _,
            cv2,
            _,  # component version
            drive_tag,
            _,  # padding 6
        ) = unpack_from(SecureBootHeaderV1._FORMAT, data)

        # check header signature 1
        if signature1 != SecureBootHeaderV1._SIGNATURE1:
            raise SPSDKError("Invalid signature")

        # check header signature 2 for version 1.1 and greater
        if (major_version > 1) or ((major_version == 1) and (minor_version >= 2)):
            if signature2 != SecureBootHeaderV1._SIGNATURE2:
                raise SPSDKError("Unexpected signature")

        product_version = BcdVersion3(swap16(pv0), swap16(pv1), swap16(pv2))
        component_version = BcdVersion3(swap16(cv0), swap16(cv1), swap16(cv2))

        obj = cls(
            digest=digest,
            version=f"{major_version}.{minor_version}",
            flags=flags,
            product_version=product_version,
            component_version=component_version,
            drive_tag=drive_tag,
        )

        obj.image_blocks = image_blocks
        obj.first_boot_section_id = first_boot_section_id
        obj.key_count = key_count  # key_blob_block = key_count
        obj.header_blocks = header_blocks
        obj.section_count = section_count
        obj.section_header_size = section_header_size
        obj.timestamp = unpack_timestamp(timestamp)

        return obj


class SectionHeaderItemV1(BaseClass):
    """Section header item representing a single entry in the section header table of SB file V1.x.

    This class encapsulates the metadata for individual sections within Secure Binary V1.x files,
    including section identification, data location, size information, and behavioral flags.

    :cvar FORMAT: Binary format string for section header serialization.
    :cvar SIZE: Size of the section header item in bytes.
    """

    FORMAT = "<4I"
    SIZE = calcsize(FORMAT)

    def __init__(
        self,
        identifier: int = 0,
        offset: int = 0,
        num_blocks: int = 0,
        flags: SecureBootFlagsV1 = SecureBootFlagsV1.NONE,
    ):
        """Initialize SectionHeaderItemV1.

        Creates a new section header item for SB1 file format with specified parameters.

        :param identifier: Unique 32-bit identifier for this section.
        :param offset: The starting cipher block for this section's data from the beginning of the image.
        :param num_blocks: The length of the section data in cipher blocks.
        :param flags: Flags that apply to the entire section, see SecureBootFlagsV1.
        """
        self.identifier = identifier
        self.offset = offset
        self.num_blocks = num_blocks
        self._flags = flags

    @property
    def flags(self) -> int:
        """Return flags value from the section header.

        The flags indicate various properties and settings for the section,
        as defined in SectionHeaderV1Flags enumeration.

        :return: Integer value representing the section flags.
        """
        return self._flags.tag

    @property
    def bootable(self) -> bool:
        """Return whether section is bootable.

        :return: True if section has bootable flag set, False otherwise.
        """
        return self.flags & SecureBootFlagsV1.ROM_SECTION_BOOTABLE.tag != 0

    @property
    def size(self) -> int:
        """Return size of exported data in bytes.

        :return: Size of the exported data in bytes.
        """
        return self.SIZE

    def __repr__(self) -> str:
        """Return string representation of SectionHeaderV1 object.

        Provides a formatted string containing the section's identifier, offset,
        number of blocks, and flags in hexadecimal format for debugging and
        logging purposes.

        :return: Formatted string representation of the section header.
        """
        return (
            f"SectionHeaderV1: ID={self.identifier}, Ofs={self.offset}, NumBlocks={self.num_blocks}, "
            f"Flag=0x{self.flags:X}"
        )

    def __str__(self) -> str:
        """Get text representation of the Header.

        Provides a formatted string containing the header's key properties including
        identifier, offset, number of blocks, and bootable status.

        :return: Formatted string with header information.
        """
        return (
            f" Identifier: 0x{self.identifier:08X}\n"
            f" Offset:     {self.offset}\n"
            f" NumBlocks:  {self.num_blocks}\n"
            f" Bootable:   {'YES' if self.bootable else 'NO'}\n"
        )

    def export(self) -> bytes:
        """Export header data to binary format.

        Serializes the header structure into binary representation using the defined FORMAT.

        :return: Binary representation of the header data.
        """
        return pack(self.FORMAT, self.identifier, self.offset, self.num_blocks, self.flags)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into SB1 header instance.

        Deserializes the provided binary data into a new header instance by unpacking
        the structured data according to the class format specification.

        :param data: Binary data to be parsed into header instance.
        :raises SPSDKError: If data size is insufficient for parsing.
        :return: New header instance created from the parsed data.
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Insufficient size")
        (identifier, offset, length, flags) = unpack_from(cls.FORMAT, data)
        return cls(identifier, offset, length, SecureBootFlagsV1.from_tag(flags))


class BootSectionHeaderV1(CmdTag):
    """Boot section header for Secure Binary version 1.

    This class represents a header for boot sections in SB1 files, derived from
    command TAG structure. The command TAG was reused to save code in Boot ROM.
    It manages section identification, block counting, and ROM flags for proper
    boot sequence handling.

    :cvar SIZE: Size of the binary representation of the header in bytes.
    """

    # size of the binary representation of the header in bytes
    SIZE = CmdHeader.SIZE

    # Mask for header flag, that identifies ROM_LAST_TAG flag
    _ROM_LAST_TAG_MASK = 1

    def __init__(self, section_id: int = 0, flags: SecureBootFlagsV1 = SecureBootFlagsV1.NONE):
        """Initialize BootSectionHeaderV1.

        :param section_id: Unique section ID as 32-bit integer.
        :param flags: Secure boot flags, see SecureBootFlagsV1 enumeration.
        """
        super().__init__()
        self.header.address = section_id
        self.header.flags = 0
        self.header.data = (
            flags.tag  # not sure here, it seems flags are duplicates as 32-bit integer too???
        )

    @property
    def section_id(self) -> int:
        """Return unique ID of the section.

        The section ID is a 32-bit number derived from the header address that uniquely
        identifies this section within the SB file structure.

        :return: Section unique identifier as 32-bit integer.
        """
        return self.header.address

    @property
    def num_blocks(self) -> int:
        """Return size of the section in number of cipher blocks.

        :return: Number of cipher blocks in the section.
        """
        return self.header.count

    @num_blocks.setter
    def num_blocks(self, value: int) -> None:
        """Set the number of cipher blocks for the section.

        :param value: Size of the section in number of cipher blocks.
        """
        self.header.count = value

    @property
    def rom_last_tag(self) -> bool:
        """Get ROM_LAST_TAG flag status.

        The last section header in an image always has its ROM_LAST_TAG flag set to help the ROM know at what point
        to stop searching.

        :return: True if ROM_LAST_TAG flag is set, False otherwise.
        """
        return self.header.flags & self._ROM_LAST_TAG_MASK != 0

    @rom_last_tag.setter
    def rom_last_tag(self, value: bool) -> None:
        """Set ROM_LAST_TAG flag in the header.

        This method modifies the flags field in the header to set or clear the ROM_LAST_TAG bit
        based on the provided boolean value.

        :param value: True to set the ROM_LAST_TAG flag, False to clear it
        """
        if value:
            self.header.flags |= self._ROM_LAST_TAG_MASK
        else:
            self.header.flags &= ~self._ROM_LAST_TAG_MASK

    @property
    def flags(self) -> SecureBootFlagsV1:
        """Get section flags from header data.

        :return: Section flags parsed from the header data.
        """
        return SecureBootFlagsV1.from_tag(self.header.data)

    @property
    def bootable(self) -> bool:
        """Return whether section is bootable.

        :return: True if the section has the bootable flag set, False otherwise.
        """
        return self.flags.tag & SecureBootFlagsV1.ROM_SECTION_BOOTABLE.tag != 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse bytes data into BootSectionHeaderV1 object.

        :param data: Raw bytes data to be parsed into header object.
        :return: Parsed BootSectionHeaderV1 instance.
        """
        cmd_tag = super(BootSectionHeaderV1, cls).parse(data)
        assert isinstance(cmd_tag, BootSectionHeaderV1)
        return cmd_tag
