#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""This module contains generic implementation of image segment."""
import abc
from typing import Optional

from spsdk.image.mem_type import MemoryType
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.registers import Registers


class SegmentBase(FeatureBaseClass):
    """Base class for image segment."""

    FEATURE = "unknown"

    def __init__(self, family: FamilyRevision) -> None:
        """Segment base Constructor.

        :param family: Chip family.
        :raises SPSDKValueError: Unsupported family.
        """
        self.family = family
        self.db = get_db(family)

    @property
    @abc.abstractmethod
    def registers(self) -> Registers:
        """Registers of segment."""

    def export(self) -> bytes:
        """Export block binary.

        :return: Binary representation of segment.
        """
        return self.registers.image_info().export()

    @classmethod
    def get_memory_types_config(cls, family: FamilyRevision) -> dict[str, dict]:
        """Get memory types data from database.

        :param family: Chip family.
        """
        return get_db(family).get_dict(cls.FEATURE, "mem_types", default={})

    @classmethod
    def get_supported_memory_types(
        cls, family: Optional[FamilyRevision] = None
    ) -> list[MemoryType]:
        """Get list of supported memory types data from database.

        :param family: Chip family.
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
