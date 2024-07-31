#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""This module contains generic implementation of image segment."""
import abc
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKValueError
from spsdk.image.mem_type import MemoryType
from spsdk.utils.abstract import BaseClass
from spsdk.utils.database import get_db, get_families
from spsdk.utils.registers import Registers


class SegmentBase(BaseClass):
    """Base class for image segment."""

    FEATURE = "unknown"

    def __init__(self, family: str, revision: str) -> None:
        """Segment base Constructor.

        :param family: Chip family.
        :param revision: Optional Chip family revision.
        :raises SPSDKValueError: Unsupported family.
        """
        if family not in self.get_supported_families():
            raise SPSDKValueError(
                f"Unsupported chip family:{family}. {family} not in {self.get_supported_families()}"
            )
        self.family = family
        self.revision = revision
        self.db = get_db(family, revision)

    @property
    @abc.abstractmethod
    def registers(self) -> Registers:
        """Registers of segment."""

    def export(self) -> bytes:
        """Export block binary.

        :return: Binary representation of segment.
        """
        return self.registers.image_info().export()

    @staticmethod
    @abc.abstractmethod
    def load_from_config(config: Dict) -> Any:
        """Load configuration file.

        :param config: Segment configuration file.
        :return: Segment object.
        """

    @abc.abstractmethod
    def create_config(self) -> str:
        """Create current configuration YAML.

        :return: Configuration of segment.
        """

    @classmethod
    def get_supported_families(cls) -> List:
        """Return list of supported families.

        :return: List of supported families.
        """
        return get_families(cls.FEATURE)

    @classmethod
    def get_memory_types_config(cls, family: str, revision: str = "latest") -> Dict[str, Dict]:
        """Get memory types data from database.

        :param family: Chip family.
        :param revision: Optional Chip family revision.
        """
        return get_db(family, revision).get_dict(cls.FEATURE, "mem_types", default={})

    @classmethod
    def get_supported_memory_types(
        cls, family: Optional[str] = None, revision: str = "latest"
    ) -> List[MemoryType]:
        """Get list of supported memory types data from database.

        :param family: Chip family.
        :param revision: Optional Chip family revision.
        """
        if family:
            return [
                MemoryType.from_label(mem_type)
                for mem_type in cls.get_memory_types_config(family, revision).keys()
            ]
        mem_types = []
        families = cls.get_supported_families()
        for supported_family in families:
            database = get_db(supported_family, revision)
            mem_types.extend(
                [
                    MemoryType.from_label(memory)
                    for memory in database.get_dict(cls.FEATURE, "mem_types").keys()
                ]
            )
        return list(set(mem_types))
