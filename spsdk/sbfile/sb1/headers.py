#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Secure Boot Header."""

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
    """Flags for SectionHeader."""

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
# Secure Boot Header Class (Version SB1.x)
########################################################################################################################
# pylint: disable=too-many-instance-attributes
class SecureBootHeaderV1(BaseClass):
    """Secure Boot Header V1."""

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

        :param version: of the format: 1.0 or 1.1 or 1.2
        :param product_version: Product version.
        :param component_version: Component version.
        :param flags: Flags associated with the entire image.
        :param drive_tag: Identifier for the disk drive or partition containing this image.
        :param digest: SHA-1 digest of all fields of the header, 20 bytes
                    The first 16 bytes (of 20 total) also act as the initialization vector for CBC-encrypted regions.
        :param timestamp: datetime of the file creation, use None for current date/time
                    Fixed value should be used only for regression testing to generate same results
        :raises SPSDKError: Invalid header version
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
        """Return key dictionary block."""
        return self.header_blocks + self.section_count * self.section_header_size

    @property
    def first_boot_tag_block(self) -> int:
        """Return first boot tag block."""
        return self.key_dictionary_block + self.key_count * 2

    @property
    def size(self) -> int:
        """Return size of the header in bytes."""
        return self._SIZE

    def __repr__(self) -> str:
        return f"Header: v{self.version}, {self.image_blocks}"

    def __str__(self) -> str:
        """Get info of Header as a string."""
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
        """Serialization to binary form.

        :param padding8: 8 padding bytes used for in the header, None to use random bytes
                This value shall be used only for regression testing to generate same results
        :return: Serialize object into bytes
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
        """Convert binary data into the instance (deserialization).

        :param data: given binary data to be decoded
        :return: the instance of secure boot header v1
        :raises SPSDKError: Raised when there is insufficient size
        :raises SPSDKError: Raised when there is invalid signature
        :raises SPSDKError: Raised when there is unexpected signature
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
    """Section header item/row in section header table in in SB file V1.x."""

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

        :param identifier: Unique 32-bit identifier for this section.
        :param offset: The starting cipher block for this section's data from the beginning of the image.
        :param num_blocks: The length of the section data in cipher blocks.
        :param flags: Flags that apply to the entire section, see SectionHeaderV1Flags
        """
        self.identifier = identifier
        self.offset = offset
        self.num_blocks = num_blocks
        self._flags = flags

    @property
    def flags(self) -> int:
        """Return flags, see SectionHeaderV1Flags."""
        return self._flags.tag

    @property
    def bootable(self) -> bool:
        """Return whether section is bootable."""
        return self.flags & SecureBootFlagsV1.ROM_SECTION_BOOTABLE.tag != 0

    @property
    def size(self) -> int:
        """Return size of exported data in bytes."""
        return self.SIZE

    def __repr__(self) -> str:
        return (
            f"SectionHeaderV1: ID={self.identifier}, Ofs={self.offset}, NumBlocks={self.num_blocks}, "
            f"Flag=0x{self.flags:X}"
        )

    def __str__(self) -> str:
        """Return Get text info of Header."""
        return (
            f" Identifier: 0x{self.identifier:08X}\n"
            f" Offset:     {self.offset}\n"
            f" NumBlocks:  {self.num_blocks}\n"
            f" Bootable:   {'YES' if self.bootable else 'NO'}\n"
        )

    def export(self) -> bytes:
        """Return serialization to binary format."""
        return pack(self.FORMAT, self.identifier, self.offset, self.num_blocks, self.flags)

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into the instance (deserialization).

        :param data: to be parsed
        :return: the new instance
        :raises SPSDKError: If size is not sufficient
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Insufficient size")
        (identifier, offset, length, flags) = unpack_from(cls.FORMAT, data)
        return cls(identifier, offset, length, SecureBootFlagsV1.from_tag(flags))


class BootSectionHeaderV1(CmdTag):
    """Header of boot section derived from command TAG.

    Note: Command TAG was reused to save some code in Boot ROM
    """

    # size of the binary representation of the header in bytes
    SIZE = CmdHeader.SIZE

    # Mask for header flag, that identifies ROM_LAST_TAG flag
    _ROM_LAST_TAG_MASK = 1

    def __init__(self, section_id: int = 0, flags: SecureBootFlagsV1 = SecureBootFlagsV1.NONE):
        """Initialize BootSectionHeaderV1.

        :param section_id: unique section ID, 32-bit int
        :param flags: see SecureBootFlagsV1
        """
        super().__init__()
        self.header.address = section_id
        self.header.flags = 0
        self.header.data = (
            flags.tag  # not sure here, it seems flags are duplicates as 32-bit integer too???
        )

    @property
    def section_id(self) -> int:
        """Return unique ID of the section, 32 number."""
        return self.header.address

    @property
    def num_blocks(self) -> int:
        """Return size of the section in number of cipher blocks."""
        return self.header.count

    @num_blocks.setter
    def num_blocks(self, value: int) -> None:
        """Setter.

        :param value: size of the section in number of cipher blocks
        """
        self.header.count = value

    @property
    def rom_last_tag(self) -> bool:
        """Return ROM_LAST_TAG flag.

        The last section header in an image always has its ROM_LAST_TAG flag set to help the ROM know at what point
        to stop searching.
        """
        return self.header.flags & self._ROM_LAST_TAG_MASK != 0

    @rom_last_tag.setter
    def rom_last_tag(self, value: bool) -> None:
        """Setter.

        :param value: ROM_LAST_TAG flag
        """
        if value:
            self.header.flags |= self._ROM_LAST_TAG_MASK
        else:
            self.header.flags &= ~self._ROM_LAST_TAG_MASK

    @property
    def flags(self) -> SecureBootFlagsV1:
        """Return section flags."""
        return SecureBootFlagsV1.from_tag(self.header.data)

    @property
    def bootable(self) -> bool:
        """Return whether section is bootable."""
        return self.flags.tag & SecureBootFlagsV1.ROM_SECTION_BOOTABLE.tag != 0

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse from bytes into BootSectionHeaderV1 object."""
        cmd_tag = super(BootSectionHeaderV1, cls).parse(data)
        assert isinstance(cmd_tag, BootSectionHeaderV1)
        return cmd_tag
