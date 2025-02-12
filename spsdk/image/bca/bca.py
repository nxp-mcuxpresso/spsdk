#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains BCA (Bootloader Configuration Area) related code."""

import datetime
import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.exceptions import SPSDKError
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

logger = logging.getLogger(__name__)


class BCA(SegmentBase):
    """BCA (Bootloader Configuration Area)."""

    FEATURE = DatabaseManager.BCA
    TAG = b"kcfg"
    SIZE = 64

    def __init__(self, family: str, revision: str = "latest") -> None:
        """BCA Constructor.

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
        """Parse binary block into BCA object.

        :param binary: binary image.
        :param offset: Offset of BCA in binary image.
        :param family: Chip family.
        :param revision: Optional Chip family revision.
        :raises SPSDKError: If given binary block contains wrong BCA tag
        """
        bca = cls(family=family, revision=revision)
        bca.registers.parse(binary[offset:])
        tag = bca.registers.find_reg("TAG")
        if tag.get_bytes_value() != cls.TAG:
            raise SPSDKError(
                f"Tag value {tag.get_bytes_value()!r} does does not match the expected value."
            )
        return bca

    def get_config(self) -> dict[str, Any]:
        """Create current configuration YAML.

        :return: Configuration of BCA Block.
        """
        config: dict[str, Any] = {}
        config["family"] = self.family
        config["revision"] = self.revision
        config["bca"] = self.registers.get_config()
        return config

    def create_config(self) -> str:
        """Create current configuration YAML.

        :return: Configuration of BCA Block.
        """
        schemas = self.get_validation_schemas(self.family, self.revision)
        return CommentedConfig(
            main_title=(
                f"BCA configuration for {self.family}.\n"
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
        bca_obj = BCA(family, revision)
        sch_cfg = get_schema_file(DatabaseManager.BCA)
        sch_family = get_schema_file("general")["family"]
        try:
            update_validation_schema_family(
                sch_family["properties"], BCA.get_supported_families(), family, revision
            )
            sch_cfg["bca"]["properties"]["bca"] = bca_obj.registers.get_validation_schema()
            return [sch_family, sch_cfg["bca"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or {revision} is not supported") from exc

    @classmethod
    def load_from_config(
        cls, config: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Creates an instance of BCA from configuration.

        :param config: Input standard configuration.
        :param search_paths: List of paths where to search for the file, defaults to None
        :return: BCA
        :raises SPSDKError: If found gap in certificates from config file. Invalid configuration.
        """
        family = config["family"]
        revision = config.get("revision", "latest")
        bca = cls(family=family, revision=revision)
        bca.registers.load_yml_config(config.get("bca", {}))
        return bca

    @staticmethod
    def get_validation_schemas_family() -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for BCA supported families.
        """
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], BCA.get_supported_families())
        return [sch_family]

    @staticmethod
    def generate_config_template(family: str, revision: str = "latest") -> str:
        """Generate configuration for selected family.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Template of BCA Block.
        """
        ret = ""

        if family in BCA.get_supported_families():
            schemas = BCA.get_validation_schemas(family, revision)
            ret = CommentedConfig(
                f"Bootloader Configuration Area (BCA) for {family}.", schemas
            ).get_template()

        return ret

    def __repr__(self) -> str:
        return "BCA Segment"

    def __str__(self) -> str:
        return (
            "BCA Segment:\n"
            f" Family:           {self.family}\n"
            f" Revision:         {self.revision}\n"
        )
