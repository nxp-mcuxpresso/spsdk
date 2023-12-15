#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCB (Flash Configuration Block) related code."""


import datetime
import os
from copy import deepcopy
from typing import Any, Dict, List

from ruamel.yaml.comments import CommentedMap as CM
from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.fcb import FCB_DATA_FOLDER, FCB_DATABASE_FILE, FCB_SCH_FILE
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.database import Database
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas


class FCB(SegmentBase):
    """FCB (Flash Configuration Block)."""

    TAG = b"FCFB"

    def __init__(self, family: str, mem_type: str, revision: str = "latest") -> None:
        """FCB Constructor.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :raises SPSDKValueError: Unsupported family.
        """
        super().__init__(family, revision)
        mem_types = FCB.get_supported_memory_types(self.family, self.revision)
        if mem_type not in mem_types:
            raise SPSDKValueError(f"Unsupported memory type:{mem_type} not in {mem_types}")
        self.mem_type = mem_type
        self._registers = Registers(family, base_endianness="little")

        block_file_name = self.get_memory_types(self.family, self.revision)[self.mem_type]
        self._registers.load_registers_from_xml(os.path.join(FCB_DATA_FOLDER, block_file_name))

    @staticmethod
    def get_database() -> Database:
        """Get the devices database."""
        return Database(FCB_DATABASE_FILE)

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
        mem_type: str = "Unknown",
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
        fcb.registers.parse(binary[offset:])
        tag = fcb.registers.find_reg("tag")
        if tag.get_bytes_value() != cls.TAG:
            raise SPSDKError(
                f"Tag value {tag.get_bytes_value()!r} does does not match the expected value."
            )
        return fcb

    @staticmethod
    def load_from_config(config: Dict) -> "FCB":
        """Load configuration file of FCB.

        :param config: FCB configuration file.
        :return: FCB object.
        """
        try:
            family = config.get("family", "Unknown")
            mem_type = config.get("type", "Unknown")
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
        config = CM()
        config["family"] = self.family
        config["revision"] = self.revision
        config["type"] = self.mem_type
        config["fcb_settings"] = self.registers.create_yml_config()
        config.yaml_set_start_comment(
            f"FCB configuration for {self.family}.\n"
            f"Created: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
            f"NXP SPSDK version: {spsdk_version}"
        )
        return CommentedConfig.convert_cm_to_yaml(config)

    @classmethod
    def get_validation_schemas(
        cls, family: str, mem_type: str, revision: str = "latest"
    ) -> List[Dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        fcb_obj = FCB(family, mem_type, revision)
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(FCB_SCH_FILE))
        try:
            sch_cfg["fcb_family_rev"]["properties"]["family"]["enum"] = FCB.get_supported_families()
            revisions = ["latest"]
            revisions.extend(
                fcb_obj.get_database().devices.get_by_name(family).revisions.revision_names
            )
            sch_cfg["fcb_family_rev"]["properties"]["revision"]["enum"] = revisions
            sch_cfg["fcb_family_rev"]["properties"]["type"]["enum"] = list(
                fcb_obj.get_supported_memory_types(fcb_obj.family, revision)
            )
            sch_cfg["fcb"]["properties"]["fcb_settings"] = fcb_obj.registers.get_validation_schema()
            return [sch_cfg["fcb_family_rev"], sch_cfg["fcb"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or {revision} is not supported") from exc

    @staticmethod
    def get_validation_schemas_family() -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for FCB supported families.
        """
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(FCB_SCH_FILE))
        sch_cfg["fcb_family_rev"]["properties"]["family"]["enum"] = FCB.get_supported_families()
        return [sch_cfg["fcb_family_rev"]]

    @staticmethod
    def generate_config_template(family: str, mem_type: str, revision: str = "latest") -> str:
        """Generate configuration for selected family.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Template of FCB Block.
        """
        ret = ""

        if family in FCB.get_supported_families():
            schemas = FCB.get_validation_schemas(family, mem_type, revision)
            override = {}
            override["family"] = family
            override["revision"] = revision
            override["type"] = mem_type

            ret = CommentedConfig(
                f"Flash Configuration Block template for {family}.",
                schemas,
                override,
            ).export_to_yaml()

        return ret

    def __repr__(self) -> str:
        return f"FCB Segment, memory type: {self.mem_type}"

    def __str__(self) -> str:
        return (
            "FCB Segment:\n"
            f" Family:           {self.family}\n"
            f" Revision:         {self.revision}\n"
            f" Memory type:      {self.mem_type}\n"
        )
