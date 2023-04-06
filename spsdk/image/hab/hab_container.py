#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains HAB related code."""

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Type

from spsdk.exceptions import SPSDKKeyError
from spsdk.image import segments
from spsdk.image.images import BootImgRT
from spsdk.utils.images import BinaryImage
from spsdk.utils.misc import BinaryPattern, find_file, find_first, load_binary

logger = logging.getLogger(__name__)


class HabEnumSegments(str, Enum):
    """Enum definition for 'par' parameter of Check Data command."""

    IVT = "ivt"
    BDT = "bdt"
    DCD = "dcd"
    XMCD = "xmcd"
    APP = "app"


@dataclass
class ConfigOptions:
    """Dataclass holding data of options section of BD config file."""

    flags: int
    start_address: int
    ivt_offset: int
    initial_load_size: int
    entrypoint_address: int
    dcd_file_path: Optional[str] = None
    xmcd_file_path: Optional[str] = None

    @staticmethod
    def parse(options: Dict[str, Any]) -> "ConfigOptions":
        """Parse config options from dictionary.

        :param options: Optiona sto be parsed
        """
        return ConfigOptions(
            flags=options["flags"],
            start_address=options["startAddress"],
            ivt_offset=options["ivtOffset"],
            initial_load_size=options["initialLoadSize"],
            entrypoint_address=options["entryPointAddress"],
            dcd_file_path=options.get("DCDFilePath"),
            xmcd_file_path=options.get("XMCDFilePath"),
        )


class HabContainer:
    """Hab container."""

    IVT_VERSION = 0x40

    def __init__(self, binary_image: BinaryImage) -> None:
        """HAB Constructor.

        :param binary_image: Binary image with required segments.
        """
        self.binary_image = binary_image

    @property
    def ivt_segment(self) -> Optional[bytes]:
        """IVT segment binary."""
        return self._get_segment_binary(HabEnumSegments.IVT)

    @property
    def bdt_segment(self) -> Optional[bytes]:
        """BDT segment binary."""
        return self._get_segment_binary(HabEnumSegments.BDT)

    @property
    def dcd_segment(self) -> Optional[bytes]:
        """DCD segment binary."""
        return self._get_segment_binary(HabEnumSegments.DCD)

    @property
    def xmcd_segment(self) -> Optional[bytes]:
        """XMCD segment binary."""
        return self._get_segment_binary(HabEnumSegments.XMCD)

    @property
    def app_segment(self) -> Optional[bytes]:
        """APP segment binary."""
        return self._get_segment_binary(HabEnumSegments.APP)

    def _get_segment_binary(self, segment: HabEnumSegments) -> Optional[bytes]:
        """Get segment by name.

        :param segment: Segment to be found
        """
        seg = find_first(self.binary_image.sub_images, lambda x: x.name == segment.value)
        return seg.binary if seg else None

    @classmethod
    def load(
        cls, bd_data: Dict[str, Any], external: List, search_paths: Optional[List[str]] = None
    ) -> "HabContainer":
        """Load the HAB container object from parsed bd_data configuration.

        :param bd_data: Dictionary of the command file content
        :param external: List of external files
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        options = ConfigOptions.parse(bd_data["options"])
        bin_image = BinaryImage(name=f"HAB", size=0, pattern=BinaryPattern("zeros"))
        # TODO: Fix lexer so the externals are parsed into bd_data
        app_bin = BinaryImage.load_binary_image(external[0], search_paths=search_paths).export()
        # IVT
        ivt = segments.SegIVT2(HabContainer.IVT_VERSION)
        ivt.app_address = options.entrypoint_address
        ivt.ivt_address = options.start_address + options.ivt_offset
        ivt.bdt_address = options.start_address + options.ivt_offset + ivt.size
        ivt_image = BinaryImage(
            name=HabEnumSegments.IVT.value,
            size=len(ivt.export()),
            offset=0,
            binary=ivt.export(),
            parent=bin_image,
        )
        bin_image.add_image(ivt_image)
        # BDT
        image_len = options.initial_load_size + len(app_bin)
        bdt = segments.SegBDT(app_start=options.start_address, app_length=image_len)
        bdt_image = BinaryImage(
            name=HabEnumSegments.BDT.value,
            size=len(bdt.export()),
            offset=ivt_image.offset + ivt.bdt_address - ivt.ivt_address,
            binary=bdt.export(),
            parent=bin_image,
        )
        bin_image.add_image(bdt_image)
        # DCD
        if options.dcd_file_path is not None:
            dcd_path = find_file(options.dcd_file_path, search_paths=search_paths)
            dcd_bin = load_binary(dcd_path)
            bin_image.add_image(
                BinaryImage(
                    name=HabEnumSegments.DCD.value,
                    size=len(dcd_bin),
                    offset=bdt_image.offset + len(bdt_image),
                    binary=dcd_bin,
                    parent=bin_image,
                )
            )
        # XMCD
        if options.xmcd_file_path is not None:
            xmcd_path = find_file(options.xmcd_file_path, search_paths=search_paths)
            xmcd_bin = load_binary(xmcd_path)
            bin_image.add_image(
                BinaryImage(
                    name=HabEnumSegments.XMCD.value,
                    size=len(xmcd_bin),
                    offset=ivt_image.offset + BootImgRT.XMCD_IVT_OFFSET,
                    binary=xmcd_bin,
                    parent=bin_image,
                )
            )
        # APP
        bin_image.add_image(
            BinaryImage(
                name=HabEnumSegments.APP.value,
                size=len(app_bin),
                offset=options.initial_load_size - options.ivt_offset,
                binary=app_bin,
                parent=bin_image,
            )
        )
        return HabContainer(binary_image=bin_image)

    @classmethod
    def parse(cls, binary: bytes) -> "HabContainer":
        """Parse existing binary into HAB container object.

        :param binary:Binary to be parsed
        """
        rt = BootImgRT.parse(binary)
        # IVT
        bin_image = BinaryImage(name=f"HAB", size=0, pattern=BinaryPattern("zeros"))
        ivt_image = BinaryImage(
            name=HabEnumSegments.IVT.value,
            size=len(rt.ivt.export()),
            offset=rt.offset - rt.ivt_offset,
            binary=rt.ivt.export(),
            parent=bin_image,
        )
        bin_image.add_image(ivt_image)
        # BDT
        if rt.bdt is not None:
            bdt_image = BinaryImage(
                name=HabEnumSegments.BDT.value,
                size=len(rt.bdt.export()),
                offset=ivt_image.offset + rt.ivt.bdt_address - rt.ivt.ivt_address,
                binary=rt.bdt.export(),
                parent=bin_image,
            )
            bin_image.add_image(bdt_image)
        # DCD
        if rt.dcd is not None:
            bin_image.add_image(
                BinaryImage(
                    name=HabEnumSegments.DCD.value,
                    size=len(rt.dcd.export()),
                    offset=ivt_image.offset + rt.ivt.dcd_address - rt.ivt.ivt_address,
                    binary=rt.dcd.export(),
                    parent=bin_image,
                )
            )
        # XMCD
        if rt.xmcd is not None:
            bin_image.add_image(
                BinaryImage(
                    name=HabEnumSegments.XMCD.value,
                    size=len(rt.xmcd.export()),
                    offset=ivt_image.offset + BootImgRT.XMCD_IVT_OFFSET,
                    binary=rt.xmcd.export(),
                    parent=bin_image,
                )
            )
        if rt.app is not None:
            bin_image.add_image(
                BinaryImage(
                    name=HabEnumSegments.APP.value,
                    size=len(rt.app.export()),
                    offset=ivt_image.offset + rt.app_offset - rt.ivt_offset,
                    binary=rt.app.export(),
                    parent=bin_image,
                )
            )
        return HabContainer(bin_image)

    def export(self) -> bytes:
        """Export into binary."""
        return self.binary_image.export()
