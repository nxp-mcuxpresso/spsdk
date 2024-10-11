#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Secure Boot Image Class."""

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
# Secure Boot Image Class (Version 1.x)
########################################################################################################################
class SecureBootV1(BaseClass):
    """SB file 1.x."""

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
        """Initialize Secure Boot Image V1.x.

        :param version: string in format #.#
            Major version of the boot image format, currently 1.
            Minor version of the boot image format, currently 1 or 2.
        :param flags: for the header, 0 by default: Flags associated with the entire image.
        :param product_version: Product version.
        :param component_version: Component version.
        :param drive_tag: For header: identifier for the disk drive or partition containing this image.
        :param dek: DEK key for encrypted SB file; this is not supported yet
        :param mac: MAC for encrypted SB file, this is not supported yet
        :param digest: SHA-1 digest of all fields of the header (it will be updated before export anyway)
            The first 16 bytes (of 20 total) also act as the initialization vector for CBC-encrypted regions.
        :param timestamp: datetime of the file creation, use None for current date/time
            Fixed value should be used only for regression testing to generate same results
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
        """Return id of first boot section."""
        return self._header.first_boot_section_id

    @first_boot_section_id.setter
    def first_boot_section_id(self, value: int) -> None:
        if value > len(self._sections):
            raise SPSDKError("Invalid length of section")
        self._header.first_boot_section_id = value

    @property
    def size(self) -> int:
        """Return size of the binary representation in bytes."""
        result = self._header.size
        for sect_hdr in self._sections_hdr_table:
            result += sect_hdr.size
        for sect in self._sections:
            result += sect.size
        result += 32  # authentication
        return result

    def __repr__(self) -> str:
        return f"Secure Boot 1, {len(self._sections)} sections"

    def __str__(self) -> str:
        """Return text info about the instance, multi-line string."""
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
        """Return sequence of all sections on the SB file."""
        return self._sections

    def append(self, section: BootSectionV1) -> None:
        """Add section into the SB file.

        :param section: to be added
        """
        assert isinstance(section, BootSectionV1)
        self._sections.append(section)

    def validate(self) -> None:
        """Validate settings.

        :raises SPSDKError: If the settings is not consistent
        """
        if not self._sections:
            raise SPSDKError("At least one section must be defined")

    def update(self) -> None:
        """Update content."""
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
        """Serialization to binary form.

        :param header_padding8: optional header padding, 8-bytes; recommended to use None to apply random value
        :param auth_padding: optional padding used after authentication; recommended to use None to apply random value
        :return: serialize the instance into binary data
        :raises SPSDKError: Invalid section data
        :raises SPSDKError: Invalid padding length
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
        """Convert binary data into the instance (deserialization).

        :param data: given binary data to be converted
        :return: converted instance
        :raises SPSDKError: raised when digest does not match
        :raises SPSDKError: Raised when section is invalid
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
