#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Bootloader Configuration Area (BCA) implementation.

This module provides functionality for handling BCA structures used in NXP MCU
bootloader configuration. The BCA contains essential configuration data that
controls bootloader behavior and system initialization parameters.
"""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers, RegistersPreValidationHook

logger = logging.getLogger(__name__)


class BCA(SegmentBase):
    """BCA (Bootloader Configuration Area) segment handler.

    This class manages the Bootloader Configuration Area which contains configuration
    data used by the bootloader during the boot process. It provides functionality
    for parsing, validating, and generating BCA segments with proper register handling.

    :cvar FEATURE: Database feature identifier for BCA operations.
    :cvar TAG: Expected binary tag identifier for BCA segments.
    :cvar SIZE: Fixed size of BCA segment in bytes.
    """

    FEATURE = DatabaseManager.BCA
    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["bca"])
    TAG = b"kcfg"
    SIZE = 64

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize BCA (Boot Configuration Area) instance.

        Creates a new BCA object for the specified chip family and initializes
        the internal registers with little-endian byte order.

        :param family: Target chip family and revision information.
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
        """Get registers of the BCA segment.

        :return: Registers object containing the BCA segment configuration.
        """
        return self._registers

    @classmethod
    def parse(cls, binary: bytes, offset: int = 0, family: Optional[FamilyRevision] = None) -> Self:
        """Parse binary block into BCA object.

        :param binary: Binary image data to parse.
        :param offset: Offset of BCA in binary image.
        :param family: Chip family specification.
        :raises SPSDKValueError: If family attribute is not specified.
        :raises SPSDKError: If given binary block contains wrong BCA tag.
        :return: Parsed BCA object instance.
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

        The method generates a configuration dictionary containing the BCA (Boot Configuration Area)
        block settings including family name, revision, and register configuration.

        :param data_path: Relative path for data files (currently unused).
        :return: Configuration of BCA Block containing family, revision and register settings.
        """
        config: Config = Config({})
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["bca"] = self.registers.get_config()
        return config

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for BCA configuration.

        Creates validation schemas for Boot Configuration Area (BCA) based on the specified
        family and revision. The method generates both family-specific and BCA-specific
        validation schemas that can be used to validate configuration data.

        :param family: Family and revision specification for target MCU.
        :raises SPSDKError: Family or revision is not supported.
        :return: List containing family validation schema and BCA validation schema.
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
        """Create BCA instance from configuration data.

        Loads Boot Configuration Area settings from the provided configuration
        and initializes a new BCA object with the specified family revision.

        :param config: Configuration object containing BCA settings and family revision data.
        :return: Configured BCA instance with loaded register values.
        """
        bca = cls(FamilyRevision.load_from_config(config))
        bca.registers.load_from_config(config.get("bca", {}))
        return bca

    def __repr__(self) -> str:
        """Return string representation of BCA Segment.

        :return: String representation of the BCA segment.
        """
        return "BCA Segment"

    def __str__(self) -> str:
        """Get string representation of BCA segment.

        Provides a formatted string containing the BCA segment information including
        the family name.

        :return: Formatted string representation of the BCA segment.
        """
        return "BCA Segment:\n" f" Family:           {self.family}\n"
