#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Secure Boot Image Class."""

from datetime import datetime
from typing import Optional, List, Sequence

from spsdk.utils.crypto import crypto_backend
from spsdk.utils.crypto.abstract import BaseClass
from spsdk.utils.misc import DebugInfo, align
from .headers import SecureBootHeaderV1, SectionHeaderItemV1, BootSectionHeaderV1
from .sections import BootSectionV1
from ..misc import BcdVersion3Format, SecBootBlckSize, BcdVersion3


########################################################################################################################
# Secure Boot Image Class (Version 1.x)
########################################################################################################################
class SecureBootV1(BaseClass):
    """SB file 1.x."""

    def __init__(self, version: str = '1.0', flags: int = 0, drive_tag: int = 0,
                 product_version: BcdVersion3Format = BcdVersion3.DEFAULT,
                 component_version: BcdVersion3Format = BcdVersion3.DEFAULT,
                 dek: Optional[bytes] = None,
                 mac: Optional[bytes] = None,
                 digest: bytes = b'\0' * 20,
                 timestamp: Optional[datetime] = None):
        """Initialize Secure Boot Image V1.x.

        :param version: string in format #.#
        Major version of the boot image format, currently 1. Minor version of the boot image format, currently 1 or 2.
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
        self._dek = dek if dek else crypto_backend().random_bytes(32)
        self._mac = mac if mac else crypto_backend().random_bytes(32)
        self._header = SecureBootHeaderV1(version=version, product_version=product_version,
                                          component_version=component_version,
                                          flags=flags, drive_tag=drive_tag, digest=digest,
                                          timestamp=timestamp)
        self._sections_hdr_table: List[SectionHeaderItemV1] = list()
        self._sections: List[BootSectionV1] = []
        self._signature = None

    def __str__(self) -> str:
        return self.info()

    @property
    def first_boot_section_id(self) -> int:
        """Return id of first boot section."""
        return self._header.first_boot_section_id

    @first_boot_section_id.setter
    def first_boot_section_id(self, value: int) -> None:
        assert value < len(self._sections)
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

    def info(self) -> str:
        """Return text info about the instance, multi-line string."""
        result = "[SB]\n"
        result += "[SB-header]\n"
        result += self._header.info()
        result += "[Sections-Header-Table]\n"
        for sect_hdr in self._sections_hdr_table:
            result += "[Section-Header]\n"
            result += sect_hdr.info()
        result += "[Sections]\n"
        for sect in self._sections:
            result += "[Section]\n"
            result += sect.info()
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

        :raise ValueError: if the settings is not consistent
        """
        if not self._sections:
            raise ValueError('At least one section must be defined')

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
        ofs_blocks = SecBootBlckSize.to_num_blocks(self._header.size + len(self._sections) * SectionHeaderItemV1.SIZE +
                                                   BootSectionHeaderV1.SIZE)
        new_hdr_table: List[SectionHeaderItemV1] = list()
        for sect in self._sections:
            sect_blcks = SecBootBlckSize.to_num_blocks(sect.size - BootSectionHeaderV1.SIZE)
            hdr = SectionHeaderItemV1(sect.section_id, ofs_blocks, sect_blcks, sect.flags)
            new_hdr_table.append(hdr)
            ofs_blocks += sect_blcks
        self._sections_hdr_table = new_hdr_table

        # update image size
        self._header.image_blocks = SecBootBlckSize.to_num_blocks(self.size)

    def export(self, header_padding8: Optional[bytes] = None, auth_padding: Optional[bytes] = None,
               dbg_info: DebugInfo = DebugInfo.disabled()) -> bytes:
        """Serialization to binary form.

        :param header_padding8: optional header padding, 8-bytes; recommended to use None to apply random value
        :param auth_padding: optional padding used after authentication; recommended to use None to apply random value
        :param dbg_info: instance allowing to debug generated output
        :return: serialize the instance into binary data
        """
        self.update()
        self.validate()
        dbg_info.append_section('SB-FILE-1.x')
        data = self._header.export(padding8=header_padding8, dbg_info=dbg_info)
        # header table
        dbg_info.append_section('Sections-Header-Table')
        for sect_hdr in self._sections_hdr_table:
            sect_hdr_data = sect_hdr.export()
            dbg_info.append_binary_data('Section-Header-Item', sect_hdr_data)
            data += sect_hdr_data
        # sections
        dbg_info.append_section('Sections')
        for sect in self._sections:
            sect_data = sect.export(dbg_info)
            assert len(sect_data) == sect.size
            data += sect_data
        # authentication: SHA1
        auth_code = crypto_backend().hash(data, 'sha1')
        dbg_info.append_binary_section('SHA1', auth_code)
        data += auth_code
        # padding
        padding_len = align(len(auth_code), SecBootBlckSize.BLOCK_SIZE) - len(auth_code)
        if auth_padding is None:
            auth_padding = crypto_backend().random_bytes(padding_len)
        assert padding_len == len(auth_padding)
        data += auth_padding
        dbg_info.append_binary_section('padding', auth_padding)
        return data

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> 'SecureBootV1':
        """Convert binary data into the instance (deserialization).

        :param data: given binary data to be converted
        :param offset: to start parsing the data
        :return: converted instance
        :raise ValueError: raised when digest does not match
        """
        obj = SecureBootV1()
        cur_pos = offset
        obj._header = SecureBootHeaderV1.parse(data, cur_pos)
        cur_pos += obj._header.size
        # sections header table
        for _ in range(obj._header.section_count):
            sect_header = SectionHeaderItemV1.parse(data, cur_pos)
            obj._sections_hdr_table.append(sect_header)
            cur_pos += sect_header.size
        # sections
        new_pos = offset + obj._header.first_boot_tag_block * SecBootBlckSize.BLOCK_SIZE
        assert new_pos >= cur_pos
        cur_pos = new_pos
        for _ in range(obj._header.section_count):
            boot_sect = BootSectionV1.parse(data, cur_pos)
            obj.append(boot_sect)
            cur_pos += boot_sect.size
        # authentication code
        sha1_auth = crypto_backend().hash(data[offset:cur_pos], 'sha1')
        if sha1_auth != data[cur_pos: cur_pos + len(sha1_auth)]:
            raise ValueError('Authentication failure: digest does not match')
        # done
        return obj
