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
    """Boot Data Table segment."""

    FORMAT = "<3L"
    SIZE = calcsize(FORMAT)

    def __init__(self, app_start: int = 0, app_length: int = 0, plugin: int = 0) -> None:
        """Initialize BDT segment.

        :param app_start: first address of the application
        :param app_length: length of the application
        :param plugin: 0 .. 2
        """
        super().__init__()
        self.app_start = app_start
        self.app_length = app_length
        self.plugin = plugin

    @property
    def plugin(self) -> int:
        """Plugin."""
        return self._plugin

    @plugin.setter
    def plugin(self, value: int) -> None:
        if value not in (0, 1, 2):
            raise SPSDKError("Plugin value must be 0 .. 2")
        self._plugin = value

    @property
    def size(self) -> int:
        """Size of the exported binary data (without padding)."""
        return self.SIZE

    def __repr__(self) -> str:
        return (
            f"BDT <ADDR: 0x{self.app_start:X}, LEN: {self.app_length} Bytes"
            f", Plugin: {self.plugin}>"
        )

    def __str__(self) -> str:
        """String representation of the SegBDT."""
        return (
            f" Start      : 0x{self.app_start:08X}\n"
            f" App Length : {size_fmt(self.app_length)} ({self.app_length} Bytes)\n"
            f" Plugin     : {'YES' if self.plugin else 'NO'}\n"
            "\n"
        )

    def export(self) -> bytes:
        """Export segment as bytes.

        :return: bytes
        """
        data = pack(self.FORMAT, self.app_start, self.app_length, self.plugin)
        data += self._padding_export()
        return data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse segment from bytes array.

        :param data: The bytes array of BDT segment
        :return: SegBDT object
        """
        return cls(*unpack_from(cls.FORMAT, data))


class HabSegmentBDT(HabSegmentBase):
    """HAB Boot Data Table segment."""

    SEGMENT_IDENTIFIER = HabSegmentEnum.BDT

    def __init__(self, bdt: SegBDT) -> None:
        """Initialization of BDT segment."""
        super().__init__()
        self.bdt = bdt
        self.app_start = self.bdt.app_start
        self.app_length = self.bdt.app_length

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the BDT HAB segment from HAB configuration.

        :param config: Hab configuration object
        :return: Instance of BDT HAB segment.
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

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of BDT HAB segment.
        """
        ivt = HabSegmentIvt.parse(data)
        offset = ivt.bdt_address - ivt.ivt_address
        segment = cls(SegBDT.parse(data[offset:]))
        segment.offset = offset
        return segment

    @property
    def offset(self) -> int:
        """Segment offset in the image."""
        if self._offset is None:
            raise SPSDKValueError("Offset not set")
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        """Set the offset for the segment.

        :param value: Offset value to set
        """
        self._offset = value

    @property
    def size(self) -> int:
        """Segment size."""
        return 0x20

    def export(self) -> bytes:
        """Export segment as bytes.

        :return: bytes
        """
        return self.bdt.export()
