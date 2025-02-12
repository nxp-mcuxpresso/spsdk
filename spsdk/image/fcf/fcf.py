#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCF (Flash Configuration Field) related code."""

import datetime
import logging
from typing import Any

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.exceptions import SPSDKError
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

logger = logging.getLogger(__name__)


class FCF(SegmentBase):
    """FCF (Flash Configuration Field)."""

    FEATURE = DatabaseManager.FCF
    SIZE = 16

    def __init__(self, family: str, revision: str = "latest") -> None:
        """FCF (Flash Configuration Field) Constructor.

        :param family: Chip family.
        :param revision: Optional Chip family revision.
        :raises SPSDKValueError: Unsupported family.
        """
        super().__init__(family, revision)
        self._registers = Registers(
            family=family,
            feature=self.FEATURE,
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
        revision: str = "latest",
    ) -> Self:
        """Parse binary block into FCF object.

        :param binary: binary image.
        :param offset: Offset of FCF in binary image.
        :param family: Chip family.
        :param revision: Optional Chip family revision.
        :raises SPSDKError: If given binary block contains wrong FCF tag
        """
        fcf = cls(family=family, revision=revision)
        if len(binary[offset:]) < FCF.SIZE:
            raise SPSDKError(
                f"Invalid input binary block size: ({len(binary[offset:])} < {FCF.SIZE})."
            )
        fcf.registers.parse(binary[offset:])
        return fcf

    @classmethod
    def load_from_config(cls, config: dict) -> Self:
        """Load configuration file of FCF.

        :param config: FCF configuration file.
        :return: FCF object.
        """
        family = config["family"]
        revision = config.get("revision", "latest")
        fcf = cls(family=family, revision=revision)
        fcf.registers.load_yml_config(config.get("fcf", {}))
        return fcf

    def get_config(self) -> dict[str, Any]:
        """Create current configuration YAML.

        :return: Configuration of FCF Block.
        """
        config: dict[str, Any] = {}
        config["family"] = self.family
        config["revision"] = self.revision
        config["fcf"] = self.registers.get_config()
        return config

    def create_config(self) -> str:
        """Create current configuration YAML.

        :return: Configuration of FCF Block.
        """
        schemas = self.get_validation_schemas(self.family, self.revision)
        return CommentedConfig(
            main_title=(
                f"FCF configuration for {self.family}.\n"
                f"Created: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
                f"NXP SPSDK version: {spsdk_version}"
            ),
            schemas=schemas,
        ).get_config(self.get_config())

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        fcf_obj = FCF(family, revision)
        sch_cfg = get_schema_file(DatabaseManager.FCF)
        sch_family = get_schema_file("general")["family"]
        try:
            update_validation_schema_family(
                sch_family["properties"], FCF.get_supported_families(), family, revision
            )
            sch_cfg["fcf"]["properties"]["fcf"] = fcf_obj.registers.get_validation_schema()
            return [sch_family, sch_cfg["fcf"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or {revision} is not supported") from exc

    @staticmethod
    def get_validation_schemas_family() -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for FCF supported families.
        """
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], FCF.get_supported_families())
        return [sch_family]

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> str:
        """Generate configuration for selected family.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Template of FCF Block.
        """
        ret = ""

        if family in FCF.get_supported_families():
            schemas = FCF.get_validation_schemas(family, revision)
            ret = CommentedConfig(
                f"Flash Configuration Field for {family}.", schemas
            ).get_template()

        return ret

    def __repr__(self) -> str:
        return "FCF Segment"

    def __str__(self) -> str:
        return (
            "FCF Segment:\n"
            f" Family:           {self.family}\n"
            f" Revision:         {self.revision}\n"
        )
