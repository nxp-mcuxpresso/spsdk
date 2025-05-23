#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module providing Image Vector Table (IVT) segment implementation for HAB containers.

This module contains classes for representing and manipulating IVT segments
which are crucial components of HAB (High Assurance Boot) secured images.
"""
import logging
from struct import calcsize, pack, unpack_from

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
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
    """Image Vector Table, IVT segment."""

    FORMAT = "<7L"
    SIZE = Header.SIZE + calcsize(FORMAT)

    def __init__(self, version: int = 0x40) -> None:
        """Initialize IVT segment.

        :param version: The version of IVT and Image format
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
        """The version of IVT and Image format."""
        return self._header.param

    @version.setter
    def version(self, value: int) -> None:
        """The version of IVT and Image format."""
        if value < 0x40 or value >= 0x4F:
            raise SPSDKError("Invalid version of IVT and image format")
        self._header.param = value

    @property
    def size(self) -> int:
        """Size of the binary data."""
        return self._header.length

    def __repr__(self) -> str:
        return (
            f"IVT <IVT:0x{self.ivt_address:X}, BDT:0x{self.bdt_address:X},"
            f" DCD:0x{self.dcd_address:X}, APP:0x{self.app_address:X}, CSF:0x{self.csf_address:X}>"
        )

    def __str__(self) -> str:
        """String representation of the SegIVT."""
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
        """Verify header data."""
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
        """Export to binary representation (serialization).

        :return: segment exported as binary data
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

        :param data: The bytes array of IVT segment
        :return: SegIVT object
        """
        header = Header.parse(data, SegmentTag.IVT.tag)
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
        """Formats 'item_address' to hex or None if address is 0.

        If provided item address is not 0, the result will be in format
        '0x' + leading zeros + number in HEX format
        If provided number is 0, function returns 'None'

        :param item_address: Address if IVT item
        :param digit_count: Number of digits to , defaults to 8
        :return: Formatted number
        """
        return f"{item_address:#0{digit_count + 2}x}" if item_address else "none"


class HabSegmentIvt(HabSegmentBase):
    """HAB-specific implementation of Image Vector Table segment."""

    SEGMENT_IDENTIFIER = HabSegmentEnum.IVT

    def __init__(self, ivt: SegIVT):
        """Initialize the segment."""
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

        :param config: Hab configuration object
        :return: Instance of IVT HAB segment.
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
        """Parse IVT segment."""
        return cls(SegIVT().parse(data))

    def export(self) -> bytes:
        """Export segment as bytes.

        :return: bytes
        """
        return self.ivt.export()

    @property
    def size(self) -> int:
        """Size of the binary data."""
        return self.ivt.size
