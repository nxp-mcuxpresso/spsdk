#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""HAB segment implementation for External Memory Configuration Data (XMCD).

This module provides classes for creating, parsing and manipulating XMCD segments
within HAB-enabled boot images. XMCD segments contain configuration data for
external memory devices like FlexSPI or SEMC interfaces.
"""

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary


class HabSegmentXMCD(HabSegmentBase):
    """HAB Segment implementation for External Memory Configuration Data (XMCD)."""

    SEGMENT_IDENTIFIER = HabSegmentEnum.XMCD
    OFFSET = 0x40

    def __init__(self, xmcd: XMCD):
        """Initialize the segment."""
        super().__init__()
        self.xmcd = xmcd
        self.offset = self.OFFSET

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the XMCD HAB segment from HAB configuration.

        :param config: Hab configuration object
        :return: Instance of XMCD HAB segment.
        """
        options = config.get_config("options")
        if options.get("XMCDFilePath"):
            segment = cls.parse(
                b"\x00" * cls.OFFSET + load_binary(options.get_input_file_name("XMCDFilePath")),
                FamilyRevision(options["family"]),
            )
            return segment
        raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present")

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse XMCD segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of XMCD HAB segment.
        """
        try:
            segment = cls(XMCD.parse(data, cls.OFFSET, family))
            segment.xmcd.verify().validate()
            return segment
        except SPSDKError as exc:
            raise SPSDKSegmentNotPresent(f"Segment {cls.__name__} is not present") from exc

    def export(self) -> bytes:
        """Export segment as bytes.

        :return: bytes
        """
        return self.xmcd.export()

    @property
    def size(self) -> int:
        """Size of the binary data."""
        return self.xmcd.size
