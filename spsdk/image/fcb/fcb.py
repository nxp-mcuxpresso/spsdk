#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCB (Flash Configuration Block) related code."""


import logging
from typing import Any

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.mem_type import MemoryType
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import Endianness, swap_bytes
from spsdk.utils.registers import Registers

logger = logging.getLogger(__name__)


class FCB(SegmentBase):
    """FCB (Flash Configuration Block)."""

    FEATURE = DatabaseManager.FCB
    TAG = b"FCFB"
    TAG_SWAPPED = swap_bytes(TAG)
    SIZE = 0x200

    def __init__(self, family: FamilyRevision, mem_type: MemoryType) -> None:
        """FCB Constructor.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :raises SPSDKValueError: Unsupported family.
        """
        super().__init__(family)
        mem_types = FCB.get_supported_memory_types(self.family)
        if mem_type not in mem_types:
            raise SPSDKValueError(
                f"Unsupported memory type:{mem_type.label} not in {[mem_type.label for mem_type in mem_types]}"
            )
        self.mem_type = mem_type
        self._registers = Registers(
            family=family,
            feature=self.FEATURE,
            base_key=["mem_types", self.mem_type.label],
            base_endianness=Endianness.LITTLE,
        )

    @property
    def registers(self) -> Registers:
        """Registers of segment."""
        return self._registers

    @classmethod
    def parse(
        cls,
        binary: bytes,
        offset: int = 0,
        family: FamilyRevision = FamilyRevision("Unknown"),
        mem_type: MemoryType = MemoryType.FLEXSPI_NOR,
    ) -> Self:
        """Parse binary block into FCB object.

        :param binary: binary image.
        :param offset: Offset of FCB in binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :raises SPSDKError: If given binary block contains wrong FCB tag
        """
        fcb = cls(family=family, mem_type=mem_type)
        if len(binary[offset:]) < FCB.SIZE:
            raise SPSDKError(
                f"Invalid input binary block size: ({len(binary[offset:])} < {FCB.SIZE})."
            )
        if binary[: (len(cls.TAG))] == cls.TAG_SWAPPED:
            logger.info("Swapped bytes order has been detected. Fixing the bytes order.")
            binary = swap_bytes(binary)
        fcb.registers.parse(binary[offset:])
        tag = fcb.registers.find_reg("tag")
        if tag.get_bytes_value() != cls.TAG:
            raise SPSDKError(
                f"Tag value {tag.get_bytes_value()!r} does does not match the expected value."
            )
        return fcb

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load FCB object from configuration.

        :param config: Configuration dictionary.
        :return: Initialized FCB object.
        """
        try:
            family = FamilyRevision.load_from_config(config)
            mem_type = MemoryType.from_label(config.get_str("type"))
            fcb = cls(family=family, mem_type=mem_type)
            fcb_settings = config.get_config("fcb_settings")
            fcb.registers.load_from_config(fcb_settings)
        except (SPSDKError, AttributeError) as exc:
            raise SPSDKValueError(f"Cannot load FCB configuration: {str(exc)}") from exc
        return fcb

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the FCB.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["type"] = self.mem_type.label
        config["fcb_settings"] = dict(self.registers.get_config())
        return config

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get validation schema for the object.

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.mem_type)

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, mem_type: MemoryType = MemoryType.FLEXSPI_NOR
    ) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param mem_type: Used memory type.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        fcb_obj = FCB(family, mem_type)
        sch_cfg = get_schema_file(DatabaseManager.FCB)
        sch_family = get_schema_file("general")["family"]
        sch_family["main_title"] = f"Flash Configuration Block template for {family}."
        try:
            update_validation_schema_family(
                sch_family["properties"], FCB.get_supported_families(), family
            )
            sch_cfg["memory_type"]["properties"]["type"]["enum"] = [
                mem_type.label for mem_type in fcb_obj.get_supported_memory_types(fcb_obj.family)
            ]
            sch_cfg["memory_type"]["properties"]["type"]["template_value"] = mem_type.label
            sch_cfg["fcb"]["properties"]["fcb_settings"] = fcb_obj.registers.get_validation_schema()
            return [sch_family, sch_cfg["memory_type"], sch_cfg["fcb"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} is not supported") from exc

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schema based on configuration.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config["type"])
        return cls.get_validation_schemas(family, mem_type)

    @staticmethod
    def get_validation_schemas_basic() -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for FCB supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.FCB)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], FCB.get_supported_families())
        return [sch_family, sch_cfg["memory_type"]]

    @classmethod
    def get_config_template(
        cls, family: FamilyRevision, mem_type: MemoryType = MemoryType.FLEXSPI_NOR
    ) -> str:
        """Get configuration for selected family.

        :param family: Family description.
        :param mem_type: Used memory type.
        :return: Template of FCB Block configuration.
        """
        schemas = cls.get_validation_schemas(family, mem_type)
        return cls._get_config_template(family, schemas)

    def __repr__(self) -> str:
        return f"FCB Segment, memory type: {self.mem_type.description}"

    def __str__(self) -> str:
        return (
            "FCB Segment:\n"
            f" Family:           {self.family}\n"
            f" Memory type:      {self.mem_type.description}\n"
        )
