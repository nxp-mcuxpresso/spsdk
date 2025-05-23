#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains BCA (Bootloader Configuration Area) related code."""

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


class BCA(SegmentBase):
    """BCA (Bootloader Configuration Area)."""

    FEATURE = DatabaseManager.BCA
    TAG = b"kcfg"
    SIZE = 64

    def __init__(self, family: FamilyRevision) -> None:
        """BCA Constructor.

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
        """Parse binary block into BCA object.

        :param binary: binary image.
        :param offset: Offset of BCA in binary image.
        :param family: Chip family.
        :raises SPSDKError: If given binary block contains wrong BCA tag
        """
        if not family:
            raise SPSDKValueError("Family attribute must be specified.")
        bca = cls(family=family)
        bca.registers.parse(binary[offset:])
        tag = bca.registers.find_reg("TAG")
        if tag.get_bytes_value() != cls.TAG:
            raise SPSDKError(
                f"Tag value {tag.get_bytes_value()!r} does does not match the expected value."
            )
        return bca

    def get_config(self, data_path: str = "./") -> Config:
        """Create current configuration YAML.

        :return: Configuration of BCA Block.
        """
        config: Config = Config({})
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["bca"] = self.registers.get_config()
        return config

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        bca_obj = BCA(family)
        sch_cfg = get_schema_file(DatabaseManager.BCA)
        sch_family = get_schema_file("general")["family"]
        try:
            update_validation_schema_family(
                sch_family["properties"], BCA.get_supported_families(), family
            )
            sch_cfg["bca"]["properties"]["bca"] = bca_obj.registers.get_validation_schema()
            return [sch_family, sch_cfg["bca"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} is not supported") from exc

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Creates an instance of BCA from configuration.

        :param config: BCA configuration.
        :return: BCA object.
        """
        bca = cls(FamilyRevision.load_from_config(config))
        bca.registers.load_from_config(config.get("bca", {}))
        return bca

    def __repr__(self) -> str:
        return "BCA Segment"

    def __str__(self) -> str:
        return "BCA Segment:\n" f" Family:           {self.family}\n"
