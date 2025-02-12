#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCB (Flash Configuration Block) related code."""


import datetime
import logging
from typing import Any

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.mem_type import MemoryType
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import Endianness, swap_bytes
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

logger = logging.getLogger(__name__)


class FCB(SegmentBase):
    """FCB (Flash Configuration Block)."""

    FEATURE = DatabaseManager.FCB
    TAG = b"FCFB"
    TAG_SWAPPED = swap_bytes(TAG)
    SIZE = 0x200

    def __init__(self, family: str, mem_type: MemoryType, revision: str = "latest") -> None:
        """FCB Constructor.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :raises SPSDKValueError: Unsupported family.
        """
        super().__init__(family, revision)
        mem_types = FCB.get_supported_memory_types(self.family, self.revision)
        if mem_type not in mem_types:
            raise SPSDKValueError(
                f"Unsupported memory type:{mem_type.label} not in {[mem_type.label for mem_type in mem_types]}"
            )
        self.mem_type = mem_type
        self._registers = Registers(
            family=family,
            feature=self.FEATURE,
            base_key=["mem_types", self.mem_type.label],
            revision=revision,
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
        family: str = "Unknown",
        mem_type: MemoryType = MemoryType.FLEXSPI_NOR,
        revision: str = "latest",
    ) -> Self:
        """Parse binary block into FCB object.

        :param binary: binary image.
        :param offset: Offset of FCB in binary image.
        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :raises SPSDKError: If given binary block contains wrong FCB tag
        """
        fcb = cls(family=family, mem_type=mem_type, revision=revision)
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

    @staticmethod
    def load_from_config(config: dict) -> "FCB":
        """Load configuration file of FCB.

        :param config: FCB configuration file.
        :return: FCB object.
        """
        try:
            family = config["family"]
            mem_type = MemoryType.from_label(config["type"])
            revision = config.get("revision", "latest")
            fcb = FCB(family=family, mem_type=mem_type, revision=revision)
            fcb_settings = config.get("fcb_settings", {})
            fcb.registers.load_yml_config(fcb_settings)
        except (SPSDKError, AttributeError) as exc:
            raise SPSDKValueError(f"Cannot load FCB configuration: {str(exc)}") from exc
        return fcb

    def create_config(self) -> str:
        """Create current configuration YAML.

        :return: Configuration of FCB Block.
        """
        config: dict[str, Any] = {}
        config["family"] = self.family
        config["revision"] = self.revision
        config["type"] = self.mem_type.label
        config["fcb_settings"] = self.registers.get_config()
        schemas = self.get_validation_schemas(self.family, self.mem_type, self.revision)
        return CommentedConfig(
            main_title=(
                f"FCB configuration for {self.family}.\n"
                f"Created: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
                f"NXP SPSDK version: {spsdk_version}"
            ),
            schemas=schemas,
        ).get_config(config)

    @classmethod
    def get_validation_schemas(
        cls, family: str, mem_type: MemoryType, revision: str = "latest"
    ) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        fcb_obj = FCB(family, mem_type, revision)
        sch_cfg = get_schema_file(DatabaseManager.FCB)
        sch_family = get_schema_file("general")["family"]
        try:
            update_validation_schema_family(
                sch_family["properties"], FCB.get_supported_families(), family, revision
            )
            sch_cfg["memory_type"]["properties"]["type"]["enum"] = [
                mem_type.label
                for mem_type in fcb_obj.get_supported_memory_types(fcb_obj.family, revision)
            ]
            sch_cfg["memory_type"]["properties"]["type"]["template_value"] = mem_type.label
            sch_cfg["fcb"]["properties"]["fcb_settings"] = fcb_obj.registers.get_validation_schema()
            return [sch_family, sch_cfg["memory_type"], sch_cfg["fcb"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or {revision} is not supported") from exc

    @staticmethod
    def get_validation_schemas_family() -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for FCB supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.FCB)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], FCB.get_supported_families())
        return [sch_family, sch_cfg["memory_type"]]

    @staticmethod
    def generate_config_template(
        family: str, mem_type: MemoryType, revision: str = "latest"
    ) -> str:
        """Generate configuration for selected family.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Template of FCB Block.
        """
        ret = ""

        if family in FCB.get_supported_families():
            schemas = FCB.get_validation_schemas(family, mem_type, revision)
            ret = CommentedConfig(
                f"Flash Configuration Block template for {family}.", schemas
            ).get_template()

        return ret

    def __repr__(self) -> str:
        return f"FCB Segment, memory type: {self.mem_type.description}"

    def __str__(self) -> str:
        return (
            "FCB Segment:\n"
            f" Family:           {self.family}\n"
            f" Revision:         {self.revision}\n"
            f" Memory type:      {self.mem_type.description}\n"
        )
