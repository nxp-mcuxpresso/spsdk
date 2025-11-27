#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HAB (High Assurance Boot) segment management utilities.

This module provides base classes and functionality for handling HAB segments,
including segment enumeration, padding segments, and abstract base segment
implementation for secure boot operations.
"""

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
    """HAB segment type enumeration for image processing.

    This enumeration defines the different types of segments that can be present
    in HAB (High Assurance Boot) images, including IVT, BDT, DCD, XMCD, CSF,
    and application segments.
    """

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
    """Base abstract segment with padding support for HAB image processing.

    This class provides a foundation for HAB (High Assurance Boot) image segments
    that require padding functionality. It manages padding data that can be
    appended to segment exports and provides common segment operations.

    :cvar PADDING_VALUE: Default byte value used for padding data.
    """

    PADDING_VALUE = 0x00

    def __init__(self) -> None:
        """Initialize the base segment.

        Sets up the basic segment with default padding value of 0.
        """
        self.padding = 0

    @property
    def padding_len(self) -> int:
        """Length of padding data in bytes.

        :return: Number of padding bytes, zero if no padding is applied.
        """
        return self.padding

    @padding_len.setter
    def padding_len(self, value: int) -> None:
        """Set new length (in bytes) of padding applied at the end of exported data.

        :param value: Length of padding in bytes.
        :raises SPSDKError: Length of padding must be >= 0.
        """
        if value < 0:
            raise SPSDKError("Length of padding must be >= 0")
        self.padding = value

    @property
    def space(self) -> int:
        """Get total space required for segment data including padding.

        The method calculates the complete size needed for the segment when exported,
        which includes both the actual segment size and any optional padding that may
        be applied during export.

        :return: Total length in bytes of segment data with padding.
        """
        return self.size + self.padding_len

    @property
    def size(self) -> int:
        """Get the size of the base segment.

        :return: Size of the segment in bytes, always returns 0 for base segment.
        """
        return 0

    def _padding_export(self) -> bytes:
        """Export padding binary data.

        The method generates padding bytes using the predefined padding value.
        The length of padding is determined by the padding_len property.

        :return: Padding bytes if padding_len > 0, otherwise empty bytes.
        """
        return bytes([self.PADDING_VALUE] * self.padding_len) if self.padding_len > 0 else b""

    def __eq__(self, other: object) -> bool:
        """Check equality between two segment objects.

        Compares two segment instances by checking if they are of the same class
        and have identical instance variables.

        :param other: Object to compare with this segment instance.
        :return: True if objects are equal, False otherwise.
        """
        return isinstance(other, self.__class__) and vars(other) == vars(self)

    def __repr__(self) -> str:
        """Return string representation of the segment object.

        :return: String containing the class name of the segment.
        """
        return f"Segment class: {self.__class__.__name__}"


class HabSegmentBase(VerifyBaseClass):
    """Base class for individual HAB segment.

    This abstract class provides the foundation for all HAB (High Assurance Boot) segment
    implementations, defining common interface and functionality for segment management
    including offset handling, data export, and configuration loading.

    :cvar SEGMENT_IDENTIFIER: Optional segment type identifier for HAB operations.
    """

    SEGMENT_IDENTIFIER: Optional[HabSegmentEnum] = None

    def __init__(self) -> None:
        """Initialize the segment.

        Sets up a new segment instance with default values. The offset is initially
        set to None and will be configured later during segment processing.
        """
        self._offset: Optional[int] = None

    def __repr__(self) -> str:
        """Return string representation of the segment object.

        This method delegates to __str__() to provide a string representation
        of the segment instance.

        :return: String representation of the segment.
        """
        return self.__str__()

    def __str__(self) -> str:
        """Get string representation of HAB segment.

        :return: String representation containing segment class name.
        """
        return f"HAB Segment: {self.__class__.__name__}"

    @property
    def offset(self) -> int:
        """Get the current offset of the segment.

        :raises SPSDKValueError: Offset is not set.
        :return: Offset value.
        """
        if self._offset is None:
            raise SPSDKValueError("Offset is not set")
        return self._offset

    @offset.setter
    def offset(self, value: int) -> None:
        """Set the offset value for the segment.

        The offset represents the position where the segment will be placed in memory
        or storage, and must be a non-negative integer value.

        :param value: The offset value to set, must be non-negative.
        :raises SPSDKValueError: If the offset value is negative.
        """
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
        :param family: Family revision information for parsing context.
        :return: Instance of segment.
        """

    @classmethod
    @abstractmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load the segment from configuration.

        :param config: Configuration object containing segment parameters.
        :return: Instance of segment created from the configuration.
        """

    @property
    @abstractmethod
    def size(self) -> int:
        """Get segment size.

        :return: Size of the segment in bytes.
        """

    def post_export(self, output_path: str) -> list[str]:
        """Post-export processing for segment size calculation.

        :param output_path: Path where the segment data was exported.
        :return: List of additional files created during export process.
        """
        return []
