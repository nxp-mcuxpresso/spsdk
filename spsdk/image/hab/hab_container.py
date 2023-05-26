#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains HAB related code."""

import logging
from datetime import datetime
from typing import List, Optional

from spsdk.image import segments
from spsdk.image.hab.config_parser import ImageConfig
from spsdk.image.hab.csf_builder import CsfBuildDirector, CsfBuilder
from spsdk.image.hab.hab_binary_image import HabBinaryImage, HabSegment
from spsdk.image.images import BootImgRT
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import BinaryPattern, load_binary

logger = logging.getLogger(__name__)


class HabContainer:
    """Hab container."""

    IVT_VERSION = 0x40

    def __init__(self, hab_image: HabBinaryImage) -> None:
        """HAB Constructor.

        :param binary_image: Binary image with required segments.
        """
        self.hab_image = hab_image

    @property
    def ivt_segment(self) -> Optional[bytes]:
        """IVT segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.IVT)
        return segment.binary if segment else None

    @property
    def bdt_segment(self) -> Optional[bytes]:
        """BDT segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.BDT)
        return segment.binary if segment else None

    @property
    def dcd_segment(self) -> Optional[bytes]:
        """DCD segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.DCD)
        return segment.binary if segment else None

    @property
    def xmcd_segment(self) -> Optional[bytes]:
        """XMCD segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.XMCD)
        return segment.binary if segment else None

    @property
    def app_segment(self) -> Optional[bytes]:
        """APP segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.APP)
        return segment.binary if segment else None

    @property
    def csf_segment(self) -> Optional[bytes]:
        """APP segment binary."""
        segment = self.hab_image.get_hab_segment(HabSegment.CSF)
        return segment.binary if segment else None

    @classmethod
    def load(
        cls,
        image_config: ImageConfig,
        search_paths: Optional[List[str]] = None,
        timestamp: Optional[datetime] = None,
    ) -> "HabContainer":
        """Load the HAB container object from parsed bd_data configuration.

        :param image_config: Image configuration
        :param search_paths: List of paths where to search for the file, defaults to None
        :param timestamp: Signature timestamp
        """
        hab_image = HabBinaryImage()
        # IVT
        ivt = segments.SegIVT2(HabContainer.IVT_VERSION)
        ivt.app_address = image_config.options.entrypoint_address
        ivt.ivt_address = image_config.options.start_address + image_config.options.ivt_offset
        ivt.bdt_address = ivt.ivt_address + ivt.size
        ivt.csf_address = 0
        hab_image.add_hab_segment(HabSegment.IVT, ivt.export())
        ivt_image = hab_image.get_hab_segment(HabSegment.IVT)
        # BDT
        bdt = segments.SegBDT(app_start=image_config.options.start_address)
        hab_image.add_hab_segment(HabSegment.BDT, bdt.export())
        # DCD
        if image_config.options.dcd_file_path is not None:
            dcd_bin = load_binary(image_config.options.dcd_file_path, search_paths=search_paths)
            hab_image.add_hab_segment(HabSegment.DCD, dcd_bin)
            ivt.dcd_address = ivt.ivt_address + HabBinaryImage.DCD_OFFSET
            ivt_image.binary = ivt.export()
        # XMCD
        if image_config.options.xmcd_file_path is not None:
            xmcd_bin = load_binary(image_config.options.xmcd_file_path, search_paths=search_paths)
            hab_image.add_hab_segment(HabSegment.XMCD, xmcd_bin)
        # APP
        app_bin = BinaryImage.load_binary_image(
            image_config.elf_file,
            search_paths=search_paths,
        )
        app_offset = image_config.options.initial_load_size - image_config.options.ivt_offset
        hab_image.add_hab_segment(HabSegment.APP, app_bin.export(), offset_override=app_offset)

        bdt.app_length = image_config.options.ivt_offset + len(hab_image)
        bdt_image = hab_image.get_hab_segment(HabSegment.BDT)
        bdt_image.binary = bdt.export()
        # Calculate CSF offset
        app_image = hab_image.get_hab_segment(HabSegment.APP)
        image_len = app_offset + len(app_image) + image_config.options.ivt_offset
        csf_offset = HabContainer._calculate_csf_offset(image_len)
        csf_offset = csf_offset - image_config.options.ivt_offset

        csf_builder = CsfBuilder(
            image_config,
            csf_offset=csf_offset,
            search_paths=search_paths,
            timestamp=timestamp,
            hab_image=hab_image,
        )
        if csf_builder.is_authenticated or csf_builder.is_encrypted:
            bdt.app_length = image_config.options.ivt_offset + csf_offset + HabBinaryImage.CSF_SIZE
            if csf_builder.is_encrypted:
                bdt.app_length += HabBinaryImage.KEYBLOB_SIZE
            bdt_image.binary = bdt.export()
            ivt.csf_address = ivt.ivt_address + csf_offset
            ivt_image.binary = ivt.export()
        # CSF
        director = CsfBuildDirector(csf_builder)
        director.build_csf()
        return HabContainer(hab_image=hab_image)

    @staticmethod
    def _calculate_csf_offset(image_len: int) -> int:
        """Calculate CSF offset from image length.

        :param image_len: Image length
        :return: CSF offset
        """
        csf_offset = image_len + (16 - (image_len % 16))
        csf_offset = ((csf_offset + 0x1000 - 1) // 0x1000) * 0x1000
        return csf_offset

    @classmethod
    def parse(cls, binary: bytes) -> "HabContainer":
        """Parse existing binary into HAB container object.

        :param binary:Binary to be parsed
        """
        rt_img = BootImgRT.parse(binary)
        # IVT
        hab_image = HabBinaryImage()
        hab_image.add_hab_segment(HabSegment.IVT, rt_img.ivt.export())
        # BDT
        if rt_img.bdt is not None:
            hab_image.add_hab_segment(HabSegment.BDT, rt_img.bdt.export())
        # DCD
        if rt_img.dcd is not None:
            hab_image.add_hab_segment(HabSegment.DCD, rt_img.dcd.export())
        # XMCD
        if rt_img.xmcd is not None:
            hab_image.add_hab_segment(HabSegment.XMCD, rt_img.xmcd.export())
        # CSF
        if rt_img.csf is not None:
            hab_image.add_hab_segment(
                HabSegment.CSF,
                rt_img.csf.export(),
                offset_override=rt_img.ivt.csf_address - rt_img.ivt.ivt_address,
            )
        # APP
        if rt_img.app is not None:
            hab_image.add_hab_segment(
                HabSegment.APP,
                rt_img.app.export(),
                offset_override=rt_img.app_offset - rt_img.ivt_offset,
            )
        return HabContainer(hab_image)

    def export(self) -> bytes:
        """Export into binary."""
        return self.hab_image.export()
