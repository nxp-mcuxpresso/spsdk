#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Boot Data Table (BDT) segment module for HAB images.

This module provides classes to create, manipulate and parse the Boot Data Table (BDT) segment
used in High Assurance Boot (HAB) images. The BDT contains information about the application
start address, length, and plugin flags required for secure boot configuration.
"""
from struct import calcsize, pack, unpack_from
from typing import Type

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.hab.segments.seg_app import HabSegmentApp
from spsdk.image.hab.segments.seg_csf import HabSegmentCSF
from spsdk.image.hab.segments.seg_ivt import HabSegmentIvt, SegIVT
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum, PaddingSegment
from spsdk.image.hab.utils import get_ivt_offset_from_cfg
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import size_fmt


class SegBDT(PaddingSegment):
    """Boot Data Table segment for HAB image processing.

    This class represents a Boot Data Table (BDT) segment used in HAB (High Assurance Boot)
    images. The BDT contains essential boot information including application start address,
    length, and plugin configuration for secure boot operations.

    :cvar FORMAT: Binary format string for BDT structure.
    :cvar SIZE: Size of the BDT segment in bytes.
    """

    FORMAT = "<3L"
    SIZE = calcsize(FORMAT)

    def __init__(self, app_start: int = 0, app_length: int = 0, plugin: int = 0) -> None:
        """Initialize BDT segment.

        :param app_start: First address of the application.
        :param app_length: Length of the application in bytes.
        :param plugin: Plugin type identifier (valid range: 0-2).
        """
        super().__init__()
        self.app_start = app_start
        self.app_length = app_length
        self.plugin = plugin

    @property
    def plugin(self) -> int:
        """Get the plugin value.

        :return: Plugin identifier value.
        """
        return self._plugin

    @plugin.setter
    def plugin(self, value: int) -> None:
        """Set plugin value for the segment.

        The plugin value determines the type of plugin to be used during boot process.

        :param value: Plugin type identifier, must be 0, 1, or 2.
        :raises SPSDKError: If plugin value is not in valid range (0-2).
        """
        if value not in (0, 1, 2):
            raise SPSDKError("Plugin value must be 0 .. 2")
        self._plugin = value

    @property
    def size(self) -> int:
        """Size of the exported binary data (without padding).

        :return: Size in bytes of the binary data without any padding applied.
        """
        return self.SIZE

    def __repr__(self) -> str:
        """Return string representation of BDT segment.

        Provides a formatted string containing the application start address,
        length, and plugin information for debugging and logging purposes.

        :return: Formatted string with BDT segment details including address, length and plugin status.
        """
        return (
            f"BDT <ADDR: 0x{self.app_start:X}, LEN: {self.app_length} Bytes"
            f", Plugin: {self.plugin}>"
        )

    def __str__(self) -> str:
        """String representation of the SegBDT.

        Returns a formatted string containing the segment's start address, application length,
        and plugin status information.

        :return: Formatted string with segment details including start address, app length, and plugin flag.
        """
        return (
            f" Start      : 0x{self.app_start:08X}\n"
            f" App Length : {size_fmt(self.app_length)} ({self.app_length} Bytes)\n"
            f" Plugin     : {'YES' if self.plugin else 'NO'}\n"
            "\n"
        )

    def export(self) -> bytes:
        """Export segment as bytes.

        Exports the Boot Data Table (BDT) segment by packing the application start address,
        application length, and plugin flag into binary format according to the segment's
        FORMAT specification, followed by any required padding.

        :return: Binary representation of the BDT segment.
        """
        data = pack(self.FORMAT, self.app_start, self.app_length, self.plugin)
        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse segment from bytes array.

        :param data: The bytes array of BDT segment.
        :return: SegBDT object.
        """
        return cls(*unpack_from(cls.FORMAT, data))


class HabSegmentBDT(HabSegmentBase):
    """HAB Boot Data Table segment.

    This class represents a Boot Data Table (BDT) segment within HAB (High Assurance Boot)
    containers, managing boot data information including application start address and length.
    The BDT segment contains essential boot parameters used by the ROM bootloader to locate
    and validate the application code.

    :cvar SEGMENT_IDENTIFIER: Identifier for BDT segment type.
    """

    SEGMENT_IDENTIFIER = HabSegmentEnum.BDT

    def __init__(self, bdt: SegBDT) -> None:
        """Initialize BDT segment with Boot Data Table.

        Sets up the segment with BDT data and extracts application start address
        and length for quick access.

        :param bdt: Boot Data Table segment containing application metadata.
        """
        super().__init__()
        self.bdt = bdt
        self.app_start = self.bdt.app_start
        self.app_length = self.bdt.app_length

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the BDT HAB segment from HAB configuration.

        Creates a BDT (Boot Data Table) segment instance by parsing the HAB configuration
        options and determining the appropriate end segment type based on configuration flags.

        :param config: HAB configuration object containing segment options and settings.
        :return: Instance of BDT HAB segment with configured parameters.
        """
        options = config.get_config("options")
        segment = cls(SegBDT(app_start=options["startAddress"]))
        end_segments: dict[int, Type[HabSegmentBase]] = {
            0: HabSegmentApp,
            1: HabSegmentCSF,
        }
        end_seg_class = end_segments[(options["flags"] & 0xF) >> 3]
        end_seg = end_seg_class.load_from_config(config)
        segment.bdt.app_length = get_ivt_offset_from_cfg(config) + end_seg.offset + end_seg.size
        segment.offset = SegIVT.SIZE
        return segment

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse BDT segment block from image binary.

        The method extracts the Boot Data Table (BDT) segment from HAB container
        binary data by first parsing the IVT to locate the BDT address offset.

        :param data: Binary data of HAB container to be parsed.
        :param family: Family revision information for parsing context.
        :return: Instance of BDT HAB segment with populated offset.
        """
        ivt = HabSegmentIvt.parse(data)
        offset = ivt.bdt_address - ivt.ivt_address
        segment = cls(SegBDT.parse(data[offset:]))
        segment.offset = offset
        return segment

    @property
    def offset(self) -> int:
        """Get segment offset in the image.

        :raises SPSDKValueError: When offset is not set.
        :return: Segment offset value in bytes.
        """
        if self._offset is None:
            raise SPSDKValueError("Offset not set")
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        """Set the offset for the segment.

        :param value: Offset value to set.
        """
        self._offset = value

    @property
    def size(self) -> int:
        """Get the size of the BDT segment.

        :return: Size of the segment in bytes (always 0x20).
        """
        return 0x20

    def export(self) -> bytes:
        """Export segment as bytes.

        Exports the Boot Data Table (BDT) segment data in binary format
        for use in HAB image creation.

        :return: Binary representation of the BDT segment.
        """
        return self.bdt.export()
