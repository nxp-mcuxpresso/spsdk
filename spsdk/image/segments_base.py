#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK base classes for image segments.

This module provides abstract base functionality for image segments used across
SPSDK image processing. It defines the core SegmentBase class that serves as
foundation for all segment implementations in the image module.
"""

import abc
from typing import Optional

from spsdk.image.mem_type import MemoryType
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.registers import Registers


class SegmentBase(FeatureBaseClass):
    """Base class for image segment implementations.

    This abstract class provides common functionality for all image segment types
    in SPSDK, including register management, binary export capabilities, and
    memory type configuration handling across different chip families.

    :cvar FEATURE: Feature identifier used for database lookups.
    """

    FEATURE = "unknown"

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize segment base with chip family configuration.

        :param family: Chip family and revision information used to configure the segment.
        :raises SPSDKValueError: Unsupported family.
        """
        self.family = family
        self.db = get_db(family)

    @property
    @abc.abstractmethod
    def registers(self) -> Registers:
        """Get registers of the segment.

        :return: Registers object containing the segment's register configuration.
        """

    def export(self) -> bytes:
        """Export segment to binary representation.

        :return: Binary data of the segment.
        """
        return self.registers.image_info().export()

    @classmethod
    def get_memory_types_config(cls, family: FamilyRevision) -> dict[str, dict]:
        """Get memory types data from database.

        :param family: Chip family.
        :return: Dictionary containing memory types configuration data.
        """
        return get_db(family).get_dict(cls.FEATURE, "mem_types", default={})

    @classmethod
    def get_supported_memory_types(
        cls, family: Optional[FamilyRevision] = None
    ) -> list[MemoryType]:
        """Get list of supported memory types data from database.

        The method retrieves memory types either for a specific chip family or all available
        memory types from the database feature configuration.

        :param family: Chip family to get memory types for. If None, returns all available types.
        :return: List of supported memory types.
        """
        if family:
            return [
                MemoryType.from_label(mem_type)
                for mem_type in cls.get_memory_types_config(family).keys()
            ]
        return [
            MemoryType.from_label(memory)
            for memory in DatabaseManager().quick_info.features_data.get_mem_types(cls.FEATURE)
        ]
