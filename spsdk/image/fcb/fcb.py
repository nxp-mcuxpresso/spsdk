#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCB (Flash Configuration Block) related code."""


import datetime
import os
from copy import deepcopy
from typing import Any, Dict, List

from ruamel.yaml.comments import CommentedMap as CM

from spsdk import version as spsdk_version
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.fcb import FCB_DATA_FOLDER, FCB_DATABASE_FILE, FCB_SCH_FILE
from spsdk.utils.database import Database
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas


class FCB:
    """FCB (Flash Configuration Block)."""

    def __init__(self, family: str, mem_type: str, revision: str = "latest") -> None:
        """FCB Constructor.

        :param family: Chip family.
        :param mem_type: Used memory type.
        :param revision: Optional Chip family revision.
        :raises SPSDKValueError: Unsupported family.
        """
        if family not in FCB.get_supported_families():
            raise SPSDKValueError(f"FCB: Unsupported chip family:{family}")
        self.family = family
        self.revision = revision
        self.mem_type = mem_type
        self._database = Database(FCB_DATABASE_FILE)
        self.mem_types: Dict = self._database.get_device_value("mem_types", family, revision)
        if mem_type not in self.mem_types.keys():
            raise SPSDKValueError(
                f"FCB: Unsupported memory type:{mem_type} not in {self.mem_types.keys()}"
            )
        self.regs = Registers(family, base_endianness="little")
        self.regs.load_registers_from_xml(os.path.join(FCB_DATA_FOLDER, self.mem_types[mem_type]))

    def export(self) -> bytes:
        """Export FCB block binary.

        :return: Binary representation of FCB.
        """
        return self.regs.image_info().export()

    def parse(self, binary: bytes) -> None:
        """Parse binary block into FCB object.

        :param binary: FCB binary image.
        :raises SPSDKValueError: Invalid input binary length.
        """
        if len(binary) != len(self.regs.image_info()):
            raise SPSDKValueError(
                "FCB parse: Invalid length of input binary."
                f" {len(binary)} != {len(self.regs.image_info())}"
            )
        for reg in self.regs.get_registers():
            reg.set_value(
                int.from_bytes(binary[reg.offset // 8 : reg.offset // 8 + reg.width // 8], "little")
            )

    @staticmethod
    def load_from_config(config: Dict) -> "FCB":
        """Load configuration file of FCB.

        :param config: FCB configuration file.
        :return: FCB object.
        """
        family = config.get("family", "Unknown")
        mem_type = config.get("type", "Unknown")
        revision = config.get("revision", "latest")
        fcb = FCB(family=family, mem_type=mem_type, revision=revision)
        fcb_settings = config.get("fcb_settings", {})
        fcb.regs.load_yml_config(fcb_settings)
        return fcb

    def create_config(self) -> str:
        """Create current configuration YAML.

        :return: Configuration of FCB Block.
        """
        config = CM()
        config["family"] = self.family
        config["revision"] = self.revision
        config["type"] = self.mem_type
        config["fcb_settings"] = self.regs.create_yml_config()
        config.yaml_set_start_comment(
            f"FCB configuration for {self.family}.\n"
            f"Created: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
            f"NXP SPSDK version: {spsdk_version}"
        )
        return ConfigTemplate.convert_cm_to_yaml(config)

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
            revisions.extend(fcb_obj._database.get_revisions(family))
            sch_cfg["fcb_family_rev"]["properties"]["revision"]["enum"] = revisions
            sch_cfg["fcb_family_rev"]["properties"]["type"]["enum"] = list(fcb_obj.mem_types.keys())
            sch_cfg["fcb"]["properties"]["fcb_settings"] = fcb_obj.regs.get_validation_schema()
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

            ret = ConfigTemplate(
                f"Trust Zone Configuration template for {family}.",
                schemas,
                override,
            ).export_to_yaml()

        return ret

    @staticmethod
    def get_supported_families() -> List[str]:
        """Return list of supported families.

        :return: List of supported families.
        """
        database = Database(FCB_DATABASE_FILE)
        return database.get_devices()

    @staticmethod
    def get_supported_memory_types(family: str, revision: str = "latest") -> List[str]:
        """Return list of supported memory types.

        :return: List of supported families.
        """
        database = Database(FCB_DATABASE_FILE)
        return list(database.get_device_value("mem_types", family, revision).keys())
