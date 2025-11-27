#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Image Vector Table (IVT) segment implementation for HAB containers.

This module provides classes for creating, parsing, and manipulating IVT segments
that are essential components of HAB (High Assurance Boot) secured images in NXP MCUs.
"""

import logging
from struct import calcsize, pack, unpack_from

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKParsingError
from spsdk.image.hab.hab_header import Header, SegmentTag
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum, PaddingSegment
from spsdk.image.hab.utils import (
    get_app_image,
    get_entrypoint_address,
    get_initial_load_size,
    get_ivt_offset_from_cfg,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)


class SegIVT(PaddingSegment):
    """HAB Image Vector Table segment implementation.

    This class represents the Image Vector Table (IVT) segment used in HAB (High Assurance Boot)
    secure boot process. The IVT contains pointers to various components of the boot image
    including application entry point, boot data, device configuration data, and command
    sequence file addresses.

    :cvar FORMAT: Binary format string for IVT data structure.
    :cvar SIZE: Total size of the IVT segment including header.
    """

    FORMAT = "<7L"
    SIZE = Header.SIZE + calcsize(FORMAT)

    def __init__(self, version: int = 0x40) -> None:
        """Initialize IVT segment.

        :param version: The version of IVT and Image format, defaults to 0x40.
        """
        super().__init__()
        self._header = Header(SegmentTag.IVT.tag, version)
        self._header.length = self.SIZE
        self.app_address = 0
        self.rs1 = 0
        self.dcd_address = 0
        self.bdt_address = 0
        self.ivt_address = 0
        self.csf_address = 0
        self.rs2 = 0

    @property
    def version(self) -> int:
        """Get the version of IVT and Image format.

        :return: Version number as integer value.
        """
        return self._header.param

    @version.setter
    def version(self, value: int) -> None:
        """Set the version of IVT and Image format.

        :param value: Version value to set, must be between 0x40 and 0x4E (inclusive).
        :raises SPSDKError: Invalid version of IVT and image format (outside valid range).
        """
        if value < 0x40 or value >= 0x4F:
            raise SPSDKError("Invalid version of IVT and image format")
        self._header.param = value

    @property
    def size(self) -> int:
        """Get the size of the binary data.

        :return: Size of the binary data in bytes.
        """
        return self._header.length

    def __repr__(self) -> str:
        """Return string representation of IVT segment.

        Provides a formatted string showing the IVT segment with all key addresses including
        IVT, BDT, DCD, APP, and CSF addresses in hexadecimal format.

        :return: Formatted string representation of the IVT segment with addresses.
        """
        return (
            f"IVT <IVT:0x{self.ivt_address:X}, BDT:0x{self.bdt_address:X},"
            f" DCD:0x{self.dcd_address:X}, APP:0x{self.app_address:X}, CSF:0x{self.csf_address:X}>"
        )

    def __str__(self) -> str:
        """String representation of the SegIVT.

        Creates a formatted string containing all IVT (Image Vector Table) segment information
        including format version, addresses for IVT, BDT, DCD, application entry point, and CSF.

        :return: Formatted string with IVT segment details.
        """
        return (
            f" Format version   : {self._format_ivt_item(self.version, digit_count=2)}\n"
            f" IVT start address: {self._format_ivt_item(self.ivt_address)}\n"
            f" BDT start address: {self._format_ivt_item(self.bdt_address)}\n"
            f" DCD start address: {self._format_ivt_item(self.dcd_address)}\n"
            f" APP entry point  : {self._format_ivt_item(self.app_address)}\n"
            f" CSF start address: {self._format_ivt_item(self.csf_address)}\n"
            "\n"
        )

    def verify(self) -> Verifier:
        """Verify IVT (Image Vector Table) segment data integrity.

        Performs comprehensive validation of the IVT segment including header verification,
        address validation, and structural consistency checks. Validates that all addresses
        are non-zero, properly ordered, and that padding fields contain expected values.

        :return: Verification results containing all validation checks and their outcomes.
        """
        ret = Verifier("IVT")
        ret.add_child(self._header.verify())
        ret.add_record(
            "IVT address is non-zero", result=self.ivt_address != 0, value=self.ivt_address
        )
        ret.add_record(
            "BDT address is non-zero", result=self.bdt_address != 0, value=self.bdt_address
        )
        ret.add_record(
            "BDT address is after IVT",
            result=self.bdt_address > self.ivt_address,
            value=self.bdt_address,
        )
        if self.dcd_address:
            ret.add_record(
                "DCD address is after IVT",
                result=self.dcd_address > self.ivt_address,
                value=self.dcd_address,
            )
        if self.csf_address:
            ret.add_record(
                "CSF address is after IVT",
                result=self.csf_address > self.ivt_address,
                value=self.csf_address,
            )
        ret.add_record(
            "IVT padding should be zero",
            result=self.padding == 0,
            value=self.padding,
        )
        return ret

    def export(self) -> bytes:
        """Export segment to binary representation.

        Serializes the IVT segment into binary format by first validating the segment
        structure, then exporting the header followed by the IVT data fields in the
        specified format.

        :raises SPSDKError: If segment validation fails.
        :return: Segment exported as binary data.
        """
        self.verify().validate()
        data = self._header.export()
        data += pack(
            self.FORMAT,
            self.app_address,
            self.rs1,
            self.dcd_address,
            self.bdt_address,
            self.ivt_address,
            self.csf_address,
            self.rs2,
        )

        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse segment from bytes array.

        Parses IVT (Image Vector Table) segment data and creates a SegIVT object with all
        necessary fields populated from the binary data.

        :param data: The bytes array containing IVT segment data
        :raises SPSDKParsingError: Invalid input data size for IVT segment
        :return: SegIVT object with parsed data
        """
        header = Header.parse(data, SegmentTag.IVT.tag)
        required_size = header.size + calcsize(cls.FORMAT)
        if len(data) < required_size:
            raise SPSDKParsingError(
                f"Invalid input data size for IVT segment: ({len(data)} < {required_size})."
            )
        obj = cls(header.param)
        (
            obj.app_address,
            obj.rs1,
            obj.dcd_address,
            obj.bdt_address,
            obj.ivt_address,
            obj.csf_address,
            obj.rs2,
        ) = unpack_from(cls.FORMAT, data, header.size)
        # Calculate IVT padding (should be zero)
        obj.padding = obj.bdt_address - obj.ivt_address - obj.size
        obj.verify().validate()
        return obj

    @staticmethod
    def _format_ivt_item(item_address: int, digit_count: int = 8) -> str:
        """Format IVT item address to hexadecimal string representation.

        If provided item address is not 0, the result will be in format
        '0x' + leading zeros + number in HEX format.
        If provided number is 0, function returns 'none'.

        :param item_address: Address of IVT item.
        :param digit_count: Number of digits to display, defaults to 8.
        :return: Formatted hexadecimal string or 'none' for zero address.
        """
        return f"{item_address:#0{digit_count + 2}x}" if item_address else "none"


class HabSegmentIvt(HabSegmentBase):
    """HAB-specific implementation of Image Vector Table segment.

    This class manages the Image Vector Table (IVT) segment for HAB (High Assurance Boot)
    operations, handling the parsing, configuration, and export of IVT data structures
    that define boot addresses and memory layout for secure boot processes.

    :cvar SEGMENT_IDENTIFIER: HAB segment type identifier for IVT segments.
    """

    SEGMENT_IDENTIFIER = HabSegmentEnum.IVT

    def __init__(self, ivt: SegIVT):
        """Initialize the segment with IVT data.

        Copies address information from the provided IVT segment and sets up
        the segment with default offset value.

        :param ivt: IVT segment containing address configuration data.
        """
        super().__init__()
        self.ivt = ivt
        self.app_address = self.ivt.app_address
        self.dcd_address = self.ivt.dcd_address
        self.bdt_address = self.ivt.bdt_address
        self.ivt_address = self.ivt.ivt_address
        self.csf_address = self.ivt.csf_address
        self.offset = 0x0

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the IVT segment from configuration.

        This method creates and configures an IVT (Image Vector Table) segment based on the
        provided HAB configuration, setting up addresses for application, IVT, BDT, CSF,
        and optionally DCD components.

        :param config: HAB configuration object containing segment options and settings.
        :return: Instance of IVT HAB segment configured according to the provided settings.
        """
        segment = SegIVT()
        options = config.get_config("options")
        segment.app_address = get_entrypoint_address(config)
        segment.ivt_address = options.get_int("startAddress") + get_ivt_offset_from_cfg(config)
        segment.bdt_address = segment.ivt_address + segment.size
        if bool(options.get_int("flags") >> 3):
            image_len = get_initial_load_size(config) + len(get_app_image(config))
            csf_offset = align(image_len + 1, 4096)
            csf_offset = csf_offset - get_ivt_offset_from_cfg(config)
            segment.csf_address = segment.ivt_address + csf_offset
        if options.get("DCDFilePath"):
            segment.dcd_address = segment.ivt_address + SegIVT.SIZE + 0x20
        return cls(segment)

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse IVT segment from binary data.

        :param data: Binary data containing the IVT segment to parse.
        :param family: Target family revision for parsing context.
        :return: New instance of the class with parsed IVT segment data.
        """
        return cls(SegIVT().parse(data))

    def export(self) -> bytes:
        """Export segment as bytes array.

        Exports the IVT (Image Vector Table) segment data in binary format
        suitable for writing to flash memory or further processing.

        :return: Binary representation of the IVT segment.
        """
        return self.ivt.export()

    @property
    def size(self) -> int:
        """Get the size of the binary data.

        :return: Size of the IVT segment in bytes.
        """
        return self.ivt.size
