#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""HAB Binary Image extension."""

from enum import Enum
from typing import Optional

from spsdk.exceptions import SPSDKKeyError
from spsdk.image import segments
from spsdk.image.images import BootImgRT
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import BinaryPattern, align_block, find_first


class HabSegment(str, Enum):
    """Enum definition for HAB segments."""

    IVT = "ivt"
    BDT = "bdt"
    DCD = "dcd"
    XMCD = "xmcd"
    CSF = "csf"
    APP = "app"


class HabBinaryImage(BinaryImage):
    """HAB binary image."""

    IVT_OFFSET = 0
    BDT_OFFSET = IVT_OFFSET + segments.SegIVT2.SIZE
    DCD_OFFSET = BDT_OFFSET + BootImgRT.BDT_SIZE
    XMCD_OFFSET = IVT_OFFSET + BootImgRT.XMCD_IVT_OFFSET

    CSF_SIZE = 0x2000
    KEYBLOB_SIZE = 0x200

    def __init__(self) -> None:
        """HAB Binary Image Constructor."""
        super().__init__(name="HAB", size=0, pattern=BinaryPattern("zeros"))

    def add_hab_segment(
        self,
        segment_name: HabSegment,
        binary: bytes,
        offset_override: Optional[int] = None,
    ) -> BinaryImage:
        """Create binary image and add it into parent image.

        :param segment_name: Segment to be added
        :param binary: Segment binary
        :param offset_override: Segment offset in the parent image
        :return: Created bootable image
        """
        segment_defintions = {
            HabSegment.IVT: (segments.SegIVT2.SIZE, self.IVT_OFFSET),
            HabSegment.BDT: (segments.SegBDT.SIZE, self.BDT_OFFSET),
            HabSegment.DCD: (None, self.DCD_OFFSET),
            HabSegment.XMCD: (None, self.XMCD_OFFSET),
            HabSegment.CSF: (BootImgRT.CSF_SIZE, None),
        }
        size, offset = segment_defintions.get(segment_name, (None, None))
        if size is None:
            size = len(binary)
        if offset_override is not None:
            offset = offset_override
        assert offset is not None
        image = BinaryImage(
            name=segment_name.value,
            size=size,
            offset=offset,
            binary=binary,
            parent=self,
        )
        self.add_image(image)
        return image

    def get_hab_segment(self, segment_name: HabSegment) -> BinaryImage:
        """Get HAB segment.

        :param segment_name: Segment to be added
        :raises SPSDKKeyError: If HAB segment not found.
        :return: Segment as binary image
        """
        seg = find_first(self.sub_images, lambda x: x.name == segment_name.value)
        if seg is None:
            raise SPSDKKeyError(f"Segment with name {segment_name} does not exist.")
        return seg

    def align_segment(self, segment_name: HabSegment, alignment: int = 16) -> None:
        """Align HAB segment.

        :param segment_name: Segment to be aligned
        :param alignment: Alignement length
        """
        seg = self.get_hab_segment(segment_name)
        assert seg.binary
        aligned_seg = align_block(seg.binary, alignment)
        seg.binary = aligned_seg
        seg.size = len(aligned_seg)
