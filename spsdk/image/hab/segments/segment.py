#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains code related to HAB segments."""

import logging
from abc import ABC, abstractmethod
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.abstract_features import VerifyBaseClass
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class HabSegmentEnum(SpsdkEnum):
    """Enum definition for HAB segments."""

    IVT = (0, "ivt", "IVT segment")
    BDT = (1, "bdt", "BDT segment")
    DCD = (2, "dcd", "DCD segment")
    XMCD = (3, "xmcd", "XMCD segment")
    CSF = (4, "csf", "CSF segment")
    APP = (5, "app", "APP segment")


########################################################################################################################
# Base Segment Class
########################################################################################################################


class PaddingSegment(ABC):
    """Base segment."""

    PADDING_VALUE = 0x00

    def __init__(self) -> None:
        """Initialize the base segment."""
        self.padding = 0

    @property
    def padding_len(self) -> int:
        """Length of padding data in bytes (zero for no padding)."""
        return self.padding

    @padding_len.setter
    def padding_len(self, value: int) -> None:
        """New length (in bytes) of padding applied at the end of exported data."""
        if value < 0:
            raise SPSDKError("Length of padding must be >= 0")
        self.padding = value

    @property
    def space(self) -> int:
        """Return length (in bytes) of the exported data including padding (if any).

        Please mind, padding is exported optionally.
        """
        return self.size + self.padding_len

    @property
    def size(self) -> int:
        """Size of base segment."""
        return 0

    def _padding_export(self) -> bytes:
        """Padding binary data, see `padding_len` for length."""
        return bytes([self.PADDING_VALUE] * self.padding_len) if self.padding_len > 0 else b""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def __repr__(self) -> str:
        return f"Segment class: {self.__class__.__name__}"


class HabSegmentBase(VerifyBaseClass):
    """Base class for individual HAB segment."""

    SEGMENT_IDENTIFIER: Optional[HabSegmentEnum] = None

    def __init__(self) -> None:
        """Initialize the segment."""
        self._offset: Optional[int] = None

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"HAB Segment: {self.__class__.__name__}"

    @property
    def offset(self) -> int:
        """Get the current offset of the segment.

        :return: Offset value or None if not set
        """
        if self._offset is None:
            raise SPSDKValueError("Offset is not set")
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        if value < 0:
            raise SPSDKValueError("Offset must be a positive integer")
        self._offset = value

    @abstractmethod
    def export(self) -> bytes:
        """Export object into bytes array.

        :return: Raw binary block of segment
        """

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes, family: FamilyRevision = FamilyRevision("unknown")) -> Self:
        """Parse segment block from image binary.

        :param data: Binary data of image to be parsed.
        :return: Instance of segment.
        """

    @classmethod
    @abstractmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the segment from configuration.

        :param config: Configuration object
        :return: Instance of segment.
        """

    @property
    @abstractmethod
    def size(self) -> int:
        """Get segment size.

        :return: Size of the segment in bytes
        """

    def post_export(self, output_path: str) -> list[str]:
        """Post-export processing for segment size calculation.

        :return: Total size of the segment after export
        """
        return []
