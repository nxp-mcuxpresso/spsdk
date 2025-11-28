#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Secure Binary version 1 image handling.

This module provides functionality for creating and managing Secure Binary v1 images
in SPSDK context, including image generation, validation, and manipulation.
"""

from datetime import datetime
from typing import Optional, Sequence

from typing_extensions import Self

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import BcdVersion3, BcdVersion3Format, SecBootBlckSize
from spsdk.sbfile.sb1.headers import BootSectionHeaderV1, SectionHeaderItemV1, SecureBootHeaderV1
from spsdk.sbfile.sb1.sections import BootSectionV1
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import align


########################################################################################################################
# Secure Binary Image Class (Version 1.x)
########################################################################################################################
class SecureBootV1(BaseClass):
    """Secure Binary file format version 1.x container.

    This class represents and manages SB (Secure Binary) file format version 1.x,
    providing functionality to create, validate, and export secure boot images
    for NXP MCUs. It handles the complete structure including headers, sections,
    and cryptographic elements required for secure boot operations.
    """

    def __init__(
        self,
        version: str = "1.0",
        flags: int = 0,
        drive_tag: int = 0,
        product_version: BcdVersion3Format = BcdVersion3.DEFAULT,
        component_version: BcdVersion3Format = BcdVersion3.DEFAULT,
        dek: Optional[bytes] = None,
        mac: Optional[bytes] = None,
        digest: bytes = b"\0" * 20,
        timestamp: Optional[datetime] = None,
    ):
        """Initialize Secure Binary Image V1.x.

        Creates a new instance of SecureBootImageV1 with specified parameters for boot image
        generation. The image supports both version 1.1 and 1.2 formats with optional encryption
        capabilities.

        :param version: Version string in format #.# (major.minor), currently supports 1.1 or 1.2.
        :param flags: Header flags associated with the entire image, defaults to 0.
        :param drive_tag: Identifier for the disk drive or partition containing this image.
        :param product_version: Product version in BCD format.
        :param component_version: Component version in BCD format.
        :param dek: DEK key for encrypted SB file (encryption not yet supported), generates random
            if None.
        :param mac: MAC for encrypted SB file (encryption not yet supported), generates random
            if None.
        :param digest: SHA-1 digest of header fields, updated before export. First 16 bytes serve
            as IV for CBC-encrypted regions.
        :param timestamp: File creation timestamp, uses current time if None. Fixed values should
            only be used for regression testing.
        """
        self._dek = dek if dek else random_bytes(32)
        self._mac = mac if mac else random_bytes(32)
        self._header = SecureBootHeaderV1(
            version=version,
            product_version=product_version,
            component_version=component_version,
            flags=flags,
            drive_tag=drive_tag,
            digest=digest,
            timestamp=timestamp,
        )
        self._sections_hdr_table: list[SectionHeaderItemV1] = []
        self._sections: list[BootSectionV1] = []
        self._signature = None

    @property
    def first_boot_section_id(self) -> int:
        """Get the ID of the first boot section.

        :return: ID of the first boot section.
        """
        return self._header.first_boot_section_id

    @first_boot_section_id.setter
    def first_boot_section_id(self, value: int) -> None:
        """Set the first boot section ID.

        This method sets the identifier of the first section to be executed during boot.
        The value must be within the valid range of existing sections.

        :param value: The section ID to set as first boot section, must be <= number of sections.
        :raises SPSDKError: If the section ID exceeds the number of available sections.
        """
        if value > len(self._sections):
            raise SPSDKError("Invalid length of section")
        self._header.first_boot_section_id = value

    @property
    def size(self) -> int:
        """Return size of the binary representation in bytes.

        Calculates the total size by summing the header size, all section header sizes,
        all section sizes, and the authentication data size (32 bytes).

        :return: Total size in bytes of the binary representation.
        """
        result = self._header.size
        for sect_hdr in self._sections_hdr_table:
            result += sect_hdr.size
        for sect in self._sections:
            result += sect.size
        result += 32  # authentication
        return result

    def __repr__(self) -> str:
        """Return string representation of the Secure Binary 1 image.

        Provides a concise summary showing the image type and number of sections contained.

        :return: String representation in format "Secure Binary 1, X sections".
        """
        return f"Secure Binary 1, {len(self._sections)} sections"

    def __str__(self) -> str:
        """Return text representation of the SB1 image instance.

        Provides a detailed multi-line string containing information about the SB1 image
        structure including header, sections header table, and all sections.

        :return: Multi-line string with detailed SB1 image information.
        """
        result = "[SB]\n"
        result += "[SB-header]\n"
        result += str(self._header)
        result += "[Sections-Header-Table]\n"
        for sect_hdr in self._sections_hdr_table:
            result += "[Section-Header]\n"
            result += str(sect_hdr)
        result += "[Sections]\n"
        for sect in self._sections:
            result += "[Section]\n"
            result += str(sect)
        return result

    @property
    def sections(self) -> Sequence[BootSectionV1]:
        """Return sequence of all sections in the SB file.

        :return: Sequence containing all boot sections present in the SB file.
        """
        return self._sections

    def append(self, section: BootSectionV1) -> None:
        """Add section into the SB file.

        :param section: Boot section to be added to the file
        :raises AssertionError: If section is not an instance of BootSectionV1
        """
        assert isinstance(section, BootSectionV1)
        self._sections.append(section)

    def validate(self) -> None:
        """Validate the image settings for consistency.

        Ensures that the image configuration is valid and contains all required
        sections before processing.

        :raises SPSDKError: If no sections are defined or settings are inconsistent.
        """
        if not self._sections:
            raise SPSDKError("At least one section must be defined")

    def update(self) -> None:
        """Update the secure boot file content.

        This method synchronizes all internal structures including header section count,
        ROM_LAST_TAG flags for bootable sections, section header table with proper
        offsets and block counts, and overall image size in blocks.
        """
        # update header
        self._header.section_count = len(self._sections)

        # update ROM_LAST_TAG - set only for last bootable section
        last = True
        for sect in reversed(self._sections):
            if sect.bootable:
                sect.rom_last_tag = last
                last = False

        # update section header table
        ofs_blocks = SecBootBlckSize.to_num_blocks(
            self._header.size
            + len(self._sections) * SectionHeaderItemV1.SIZE
            + BootSectionHeaderV1.SIZE
        )
        new_hdr_table: list[SectionHeaderItemV1] = []
        for sect in self._sections:
            sect_blcks = SecBootBlckSize.to_num_blocks(sect.size - BootSectionHeaderV1.SIZE)
            hdr = SectionHeaderItemV1(sect.section_id, ofs_blocks, sect_blcks, sect.flags)
            new_hdr_table.append(hdr)
            ofs_blocks += sect_blcks
        self._sections_hdr_table = new_hdr_table

        # update image size
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.size)

    def export(
        self,
        header_padding8: Optional[bytes] = None,
        auth_padding: Optional[bytes] = None,
    ) -> bytes:
        """Export the SB1 image to binary format.

        The method serializes the complete SB1 image including header, section table,
        sections data, authentication hash, and padding to create the final binary output.

        :param header_padding8: Optional header padding, 8-bytes; recommended to use None
            to apply random value
        :param auth_padding: Optional padding used after authentication; recommended to use
            None to apply random value
        :return: Binary representation of the SB1 image
        :raises SPSDKError: Invalid section data or invalid padding length
        """
        self.update()
        self.validate()
        data = self._header.export(padding8=header_padding8)
        # header table
        for sect_hdr in self._sections_hdr_table:
            sect_hdr_data = sect_hdr.export()
            data += sect_hdr_data
        # sections
        for sect in self._sections:
            sect_data = sect.export()
            if len(sect_data) != sect.size:
                raise SPSDKError("Invalid section data")
            data += sect_data
        # authentication: SHA1
        auth_code = get_hash(data, EnumHashAlgorithm.SHA1)
        data += auth_code
        # padding
        padding_len = align(len(auth_code), SecBootBlckSize.BLOCK_SIZE) - len(auth_code)
        if auth_padding is None:
            auth_padding = random_bytes(padding_len)
        if padding_len != len(auth_padding):
            raise SPSDKError("Invalid padding length")
        data += auth_padding
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse binary data into SecureBoot image instance.

        Deserializes binary data by parsing the secure boot header, section header table,
        boot sections, and validates the authentication digest.

        :param data: Binary data to be deserialized into SecureBoot image instance.
        :return: Parsed SecureBoot image instance.
        :raises SPSDKError: Invalid section positioning detected.
        :raises SPSDKError: Authentication failure when digest does not match.
        """
        obj = cls()
        cur_pos = 0
        obj._header = SecureBootHeaderV1.parse(data)
        cur_pos += obj._header.size
        # sections header table
        for _ in range(obj._header.section_count):
            sect_header = SectionHeaderItemV1.parse(data[cur_pos:])
            obj._sections_hdr_table.append(sect_header)
            cur_pos += sect_header.size
        # sections
        new_pos = obj._header.first_boot_tag_block * SecBootBlckSize.BLOCK_SIZE
        if new_pos < cur_pos:
            raise SPSDKError("Invalid section")
        cur_pos = new_pos
        for _ in range(obj._header.section_count):
            boot_sect = BootSectionV1.parse(data[cur_pos:])
            obj.append(boot_sect)
            cur_pos += boot_sect.size
        # authentication code
        sha1_auth = get_hash(data[:cur_pos], EnumHashAlgorithm.SHA1)
        if sha1_auth != data[cur_pos : cur_pos + len(sha1_auth)]:
            raise SPSDKError("Authentication failure: digest does not match")
        # done
        return obj
