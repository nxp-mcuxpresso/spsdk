#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module containing the HAB Application segment implementation.

This module provides the HabSegmentApp class that represents the Application segment
in the High Assurance Boot (HAB) container.
"""
import logging

from typing_extensions import Self

from spsdk.exceptions import SPSDKParsingError
from spsdk.image.hab.segments.seg_ivt import HabSegmentIvt
from spsdk.image.hab.segments.segment import HabSegmentBase, HabSegmentEnum
from spsdk.image.hab.utils import (
    get_app_image,
    get_initial_load_size,
    get_ivt_offset_from_cfg,
    get_reset_vector,
)
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align_block
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)


class HabSegmentApp(HabSegmentBase):
    """APP HAB segment class."""

    SEGMENT_IDENTIFIER = HabSegmentEnum.APP

    def __init__(self, binary: bytes) -> None:
        """XMCD HAB segment initialization.

        :param offset: Segment offset
        :param binary: Application binary
        """
        self.binary = binary

    def __repr__(self) -> str:
        return "APP HAB segment"

    def __str__(self) -> str:
        """Get info of App Segment as a string."""
        info = "CSF APP segment"
        info += f" Length:                      {len(self.binary)}\n"
        info += f" Offset:                      {self.offset}\n"
        return info

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the APP HAB segment from HAB configuration.

        :param config: Hab configuration object
        :return: Instance of APP HAB segment.
        """
        options = config.get_config("options")
        app_bin = get_app_image(config).export()
        if (options["flags"] & 0xF) >> 3:
            app_bin = align_block(app_bin, 16)
        offset = get_initial_load_size(config) - get_ivt_offset_from_cfg(config)
        segment = cls(app_bin)
        segment.offset = offset
        return segment

    def export(self) -> bytes:
        """Export object into bytes array.

        :return: Raw binary block of segment
        """
        return self.binary

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse APP segment block from image binary.

        :param data: Binary data of HAB container to be parsed.
        :return: Instance of APP HAB segment.
        """
        ivt = HabSegmentIvt.parse(data)

        def get_app_offset() -> int:
            """Get app offset from known possible offsets."""
            known_offsets = [0x100, 0x400, 0xC00, 0x1000, 0x2000]
            for offset in known_offsets:
                logger.debug(f"Testing the potential application on offset {offset}")
                reset_vector = get_reset_vector(data[offset:])
                if reset_vector == 0:
                    logger.debug("The reset vector cannot be 0x0")
                    continue
                # there are some cases where the reset vector and the entrypoint address are not same
                # reset vector inside the given range is accepted
                range_start = ivt.app_address - 0x400
                range_end = ivt.app_address + len(data)
                if reset_vector not in range(range_start, range_end):
                    logger.debug(
                        f"The reset vector {reset_vector:#x} is not inside the range {range_start:#x}:{range_end:#x}"
                    )
                    continue
                if not reset_vector % 2:
                    logger.debug(
                        "The least significant bit is not set to 1, indicating Thumb state execution"
                    )
                    continue
                return offset
            raise SPSDKParsingError("Application offset could not be found")

        offset = get_app_offset()
        end = ivt.csf_address - ivt.ivt_address if ivt.csf_address > 0 else len(data)
        binary = data[offset:end]
        segment = cls(binary)
        segment.offset = offset
        return segment

    @property
    def size(self) -> int:
        """Get size of the segment."""
        return len(self.binary)

    def verify(self) -> Verifier:
        """Verify App segment data."""
        ret = Verifier("Application segment")
        ret.add_record_bytes("Application binary", self.binary)
        ret.add_record_range("Application offset", self.offset)
        return ret
