#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains FCF (Flash Configuration Field) related code."""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers

logger = logging.getLogger(__name__)


class FCF(SegmentBase):
    """FCF (Flash Configuration Field)."""

    FEATURE = DatabaseManager.FCF
    SIZE = 16

    def __init__(self, family: FamilyRevision) -> None:
        """FCF (Flash Configuration Field) Constructor.

        :param family: Chip family.
        :raises SPSDKValueError: Unsupported family.
        """
        super().__init__(family)
        self._registers = Registers(
            family=family,
            feature=self.FEATURE,
            base_endianness=Endianness.LITTLE,
        )

    @property
    def registers(self) -> Registers:
        """Registers of segment."""
        return self._registers

    @classmethod
    def parse(cls, binary: bytes, offset: int = 0, family: Optional[FamilyRevision] = None) -> Self:
        """Parse binary block into FCF object.

        :param binary: binary image.
        :param offset: Offset of FCF in binary image.
        :param family: Chip family.
        :raises SPSDKError: If given binary block contains wrong FCF tag
        """
        if not family:
            raise SPSDKValueError("Family attribute must be specified.")
        fcf = cls(family=family)
        if len(binary[offset:]) < FCF.SIZE:
            raise SPSDKError(
                f"Invalid input binary block size: ({len(binary[offset:])} < {FCF.SIZE})."
            )
        fcf.registers.parse(binary[offset:])
        return fcf

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load configuration file of FCF.

        :param config: FCF configuration.
        :return: FCF object.
        """
        fcf = cls(FamilyRevision.load_from_config(config))
        fcf.registers.load_from_config(config.get("fcf", {}))
        return fcf

    def get_config(self, data_path: str = "./") -> Config:
        """Create current configuration YAML.

        :return: Configuration of FCF Block.
        """
        config: Config = Config({})
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["fcf"] = self.registers.get_config()
        return config

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        fcf_obj = FCF(family)
        sch_cfg = get_schema_file(DatabaseManager.FCF)
        sch_family = get_schema_file("general")["family"]
        try:
            update_validation_schema_family(
                sch_family["properties"], FCF.get_supported_families(), family
            )
            sch_cfg["fcf"]["properties"]["fcf"] = fcf_obj.registers.get_validation_schema()
            return [sch_family, sch_cfg["fcf"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} is not supported") from exc

    def __repr__(self) -> str:
        return "FCF Segment"

    def __str__(self) -> str:
        return "FCF Segment:\n" f" Family:           {self.family}\n"
