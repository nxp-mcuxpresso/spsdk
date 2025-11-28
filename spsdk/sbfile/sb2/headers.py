#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2 image header management utilities.

This module provides functionality for handling Secure Binary version 2 (SB2) image headers,
including header creation, validation, and serialization for NXP MCU secure provisioning.
"""

from datetime import datetime
from struct import calcsize, pack, unpack_from
from typing import Optional

from typing_extensions import Self

from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.misc import BcdVersion3, pack_timestamp, unpack_timestamp
from spsdk.utils.abstract import BaseClass
from spsdk.utils.misc import swap16


########################################################################################################################
# Image Header Class (Version SB2)
########################################################################################################################
# pylint: disable=too-many-instance-attributes
class ImageHeaderV2(BaseClass):
    """SB2 Image Header Version 2 implementation.

    This class represents the header structure for Secure Binary version 2 image files,
    managing metadata including version information, build details, cryptographic nonce,
    and structural pointers for boot image processing.

    :cvar FORMAT: Binary format string for header serialization.
    :cvar SIZE: Total size of the header structure in bytes.
    :cvar SIGNATURE1: Primary signature identifier 'STMP'.
    :cvar SIGNATURE2: Secondary signature identifier 'sgtl'.
    """

    FORMAT = "<16s4s4s2BH4I4H4sQ12HI4s"
    SIZE = calcsize(FORMAT)
    SIGNATURE1 = b"STMP"
    SIGNATURE2 = b"sgtl"

    def __init__(
        self,
        version: str = "2.0",
        product_version: str = "1.0.0",
        component_version: str = "1.0.0",
        build_number: int = 0,
        flags: int = 0x08,
        nonce: Optional[bytes] = None,
        timestamp: Optional[datetime] = None,
        padding: Optional[bytes] = None,
    ) -> None:
        """Initialize Image Header Version 2.x.

        Creates a new SB2 image header with specified version information, security parameters,
        and optional testing configurations.

        :param version: The image version value (default: 2.0)
        :param product_version: The product version (default: 1.0.0)
        :param component_version: The component version (default: 1.0.0)
        :param build_number: The build number value (default: 0)
        :param flags: The flags value (default: 0x08)
        :param nonce: The NONCE value for cryptographic operations
        :param timestamp: Timestamp for the header; None to use current time
        :param padding: Header padding (8 bytes) for testing; None to use random values
        """
        self.nonce = nonce
        self.version = version
        self.flags = flags
        self.image_blocks = 0  # will be updated from boot image
        self.first_boot_tag_block = 0
        self.first_boot_section_id = 0
        self.offset_to_certificate_block = 0  # will be updated from boot image
        self.header_blocks = 0  # will be calculated in the BootImage later
        self.key_blob_block = 8
        self.key_blob_block_count = 5
        self.max_section_mac_count = 0  # will be calculated in the BootImage later
        self.timestamp = (
            timestamp
            if timestamp is not None
            else datetime.fromtimestamp(int(datetime.now().timestamp()))
        )
        self.product_version: BcdVersion3 = BcdVersion3.to_version(product_version)
        self.component_version: BcdVersion3 = BcdVersion3.to_version(component_version)
        self.build_number = build_number
        self.padding = padding

    def __repr__(self) -> str:
        """Return string representation of the header object.

        Provides a formatted string containing the version and image blocks information
        for debugging and logging purposes.

        :return: String representation in format "Header: v{version}, {image_blocks}".
        """
        return f"Header: v{self.version}, {self.image_blocks}"

    def flags_desc(self) -> str:
        """Get flag description based on current flags value.

        Returns a human-readable description indicating whether the flags represent
        a signed or unsigned state.

        :return: "Signed" if flags equals 0x8, otherwise "Unsigned".
        """
        return "Signed" if self.flags == 0x8 else "Unsigned"

    def __str__(self) -> str:
        """Get string representation of the SB2 header.

        Provides a formatted string containing all header fields including version,
        flags, block information, timestamps, and version details.

        :return: Formatted string with header information.
        """
        nfo = str()
        nfo += f" Version:              {self.version}\n"
        if self.nonce is not None:
            nfo += f" Digest:               {self.nonce.hex().upper()}\n"
        nfo += f" Flag:                 0x{self.flags:X} ({self.flags_desc()})\n"
        nfo += f" Image Blocks:         {self.image_blocks}\n"
        nfo += f" First Boot Tag Block: {self.first_boot_tag_block}\n"
        nfo += f" First Boot SectionID: {self.first_boot_section_id}\n"
        nfo += f" Offset to Cert Block: {self.offset_to_certificate_block}\n"
        nfo += f" Key Blob Block:       {self.key_blob_block}\n"
        nfo += f" Header Blocks:        {self.header_blocks}\n"
        nfo += f" Sections MAC Count:   {self.max_section_mac_count}\n"
        nfo += f" Key Blob Block Count: {self.key_blob_block_count}\n"
        nfo += f" Timestamp:            {self.timestamp.strftime('%H:%M:%S (%d.%m.%Y)')}\n"
        nfo += f" Product Version:      {self.product_version}\n"
        nfo += f" Component Version:    {self.component_version}\n"
        nfo += f" Build Number:         {self.build_number}\n"
        return nfo

    def export(self, padding: Optional[bytes] = None) -> bytes:
        """Export SB2 header object into binary format.

        The method serializes all header fields including nonce, version information,
        flags, and various block offsets into a packed binary representation suitable
        for SB2 file format.

        :param padding: Header padding 8 bytes for testing purposes; None to use random value
        :return: Binary representation of the SB2 header
        :raises SPSDKError: When nonce format is incorrect
        :raises SPSDKError: When padding length is not 8 bytes
        :raises SPSDKError: When resulting header length is incorrect
        """
        if not isinstance(self.nonce, bytes) or len(self.nonce) != 16:
            raise SPSDKError("Format is incorrect")
        major_version, minor_version = [int(v) for v in self.version.split(".")]
        product_version_words = [swap16(v) for v in self.product_version.nums]
        component_version_words = [swap16(v) for v in self.product_version.nums]
        padding = padding or self.padding
        if padding is None:
            padding = random_bytes(8)
        else:
            if len(padding) != 8:
                raise SPSDKError("Invalid length of padding")

        result = pack(
            self.FORMAT,
            self.nonce,
            # padding 8 bytes
            padding,
            self.SIGNATURE1,
            # header version
            major_version,
            minor_version,
            self.flags,
            self.image_blocks,
            self.first_boot_tag_block,
            self.first_boot_section_id,
            self.offset_to_certificate_block,
            self.header_blocks,
            self.key_blob_block,
            self.key_blob_block_count,
            self.max_section_mac_count,
            self.SIGNATURE2,
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
            self.build_number,
            # padding[4]
            padding[4:],
        )
        if len(result) != self.SIZE:
            raise SPSDKError("Invalid length of header")
        return result

    # pylint: disable=too-many-locals
    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse SB2 header from binary data.

        Deserializes the SB2 header structure from its binary representation, validating
        signatures and extracting all header fields including version information,
        flags, and various block offsets.

        :param data: Binary data containing the SB2 header structure.
        :return: Parsed instance of the SB2 header.
        :raises SPSDKError: If data is insufficient or header signatures don't match.
        """
        if cls.SIZE > len(data):
            raise SPSDKError("Insufficient amount of data")
        (
            nonce,
            # padding0
            _,
            signature1,
            # header version
            major_version,
            minor_version,
            flags,
            image_blocks,
            first_boot_tag_block,
            first_boot_section_id,
            offset_to_certificate_block,
            header_blocks,
            key_blob_block,
            key_blob_block_count,
            max_section_mac_count,
            signature2,
            raw_timestamp,
            # product version
            pv0,
            _,
            pv1,
            _,
            pv2,
            _,
            # component version
            cv0,
            _,
            cv1,
            _,
            cv2,
            _,
            build_number,
            # padding1
            _,
        ) = unpack_from(cls.FORMAT, data)

        # check header signature 1
        if signature1 != cls.SIGNATURE1:
            raise SPSDKError("SIGNATURE #1 doesn't match")

        # check header signature 2
        if signature2 != cls.SIGNATURE2:
            raise SPSDKError("SIGNATURE #2 doesn't match")

        obj = cls(
            version=f"{major_version}.{minor_version}",
            flags=flags,
            product_version=f"{swap16(pv0):X}.{swap16(pv1):X}.{swap16(pv2):X}",
            component_version=f"{swap16(cv0):X}.{swap16(cv1):X}.{swap16(cv2):X}",
            build_number=build_number,
        )

        obj.nonce = nonce
        obj.image_blocks = image_blocks
        obj.first_boot_tag_block = first_boot_tag_block
        obj.first_boot_section_id = first_boot_section_id
        obj.offset_to_certificate_block = offset_to_certificate_block
        obj.header_blocks = header_blocks
        obj.key_blob_block = key_blob_block
        obj.key_blob_block_count = key_blob_block_count
        obj.max_section_mac_count = max_section_mac_count
        obj.timestamp = unpack_timestamp(raw_timestamp)

        return obj
