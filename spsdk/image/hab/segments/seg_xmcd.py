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
    """HAB Segment implementation for External Memory Configuration Data (XMCD).

    This class manages XMCD segments within HAB (High Assurance Boot) containers,
    providing functionality to load, parse, and export external memory configuration
    data used for configuring external memory interfaces during boot process.

    :cvar SEGMENT_IDENTIFIER: HAB segment type identifier for XMCD segments.
    :cvar OFFSET: Default offset position for XMCD data in the segment.
    """

    SEGMENT_IDENTIFIER = HabSegmentEnum.XMCD
    OFFSET = 0x40

    def __init__(self, xmcd: XMCD):
        """Initialize the XMCD segment.

        Creates a new XMCD segment instance with the provided XMCD configuration
        and sets the default offset value.

        :param xmcd: XMCD configuration object to be used in this segment.
        """
        super().__init__()
        self.xmcd = xmcd
        self.offset = self.OFFSET

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the XMCD HAB segment from HAB configuration.

        Creates an XMCD HAB segment instance by loading the XMCD data from the file path
        specified in the configuration options.

        :param config: HAB configuration object containing segment options.
        :raises SPSDKSegmentNotPresent: When XMCDFilePath is not specified in configuration.
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

        The method parses binary data to create an XMCD HAB segment instance, verifies and
        validates the parsed XMCD data.

        :param data: Binary data of HAB container to be parsed.
        :param family: Family revision for parsing context, defaults to unknown.
        :raises SPSDKSegmentNotPresent: When XMCD segment is not present in the data.
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

        Exports the XMCD (External Memory Configuration Data) segment data in binary format
        for use in HAB (High Assurance Boot) image processing.

        :return: Binary representation of the XMCD segment.
        """
        return self.xmcd.export()

    @property
    def size(self) -> int:
        """Get size of the binary data.

        :return: Size of the XMCD binary data in bytes.
        """
        return self.xmcd.size
