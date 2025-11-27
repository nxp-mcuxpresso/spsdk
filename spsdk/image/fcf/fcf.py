#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Flash Configuration Field (FCF) management utilities.

This module provides functionality for handling Flash Configuration Field data
structures used in NXP MCU boot process. The FCF contains critical flash
configuration parameters that determine how the bootloader configures the
external flash memory.
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


class FCF(SegmentBase):
    """FCF (Flash Configuration Field) segment for NXP MCU images.

    This class represents and manages Flash Configuration Field data, which contains
    critical flash memory configuration settings for NXP microcontrollers. The FCF
    segment defines flash security settings, protection levels, and boot configuration
    options that are programmed into the device's flash memory.

    :cvar FEATURE: Database feature identifier for FCF operations.
    :cvar SIZE: Fixed size of FCF segment in bytes (16 bytes).
    """

    FEATURE = DatabaseManager.FCF
    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["fcf"])
    SIZE = 16

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize FCF (Flash Configuration Field) instance.

        Creates a new FCF object for the specified chip family and initializes
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
        """Get registers of the FCF segment.

        :return: Registers object containing the FCF segment configuration.
        """
        return self._registers

    @classmethod
    def parse(cls, binary: bytes, offset: int = 0, family: Optional[FamilyRevision] = None) -> Self:
        """Parse binary block into FCF object.

        :param binary: Binary image containing FCF data.
        :param offset: Offset of FCF in binary image.
        :param family: Chip family specification.
        :raises SPSDKValueError: If family attribute is not specified.
        :raises SPSDKError: If binary block size is insufficient for FCF parsing.
        :return: Parsed FCF object instance.
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

        The method creates FCF object from configuration data and loads register values
        from the FCF section of the configuration.

        :param config: FCF configuration data containing family revision and register settings.
        :return: FCF object with loaded configuration.
        """
        fcf = cls(FamilyRevision.load_from_config(config))
        fcf.registers.load_from_config(config.get("fcf", {}))
        return fcf

    def get_config(self, data_path: str = "./") -> Config:
        """Get current configuration YAML.

        Creates a configuration dictionary containing the FCF (Flash Configuration Field)
        block settings including family name, revision, and register configuration.

        :param data_path: Path to data directory (currently unused).
        :return: Configuration dictionary with FCF block settings.
        """
        config: Config = Config({})
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["fcf"] = self.registers.get_config()
        return config

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for FCF configuration.

        Creates validation schemas for Flash Configuration Field (FCF) based on the specified
        family and revision. The method generates both family-specific and FCF-specific
        validation schemas that can be used to validate configuration data.

        :param family: Family and revision specification for target MCU.
        :raises SPSDKError: Family or revision is not supported.
        :return: List containing family validation schema and FCF validation schema.
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
        """Return string representation of FCF segment.

        :return: String identifier for the FCF segment object.
        """
        return "FCF Segment"

    def __str__(self) -> str:
        """Get string representation of FCF segment.

        Provides a formatted string containing the FCF segment information including
        the family name.

        :return: Formatted string representation of the FCF segment.
        """
        return "FCF Segment:\n" f" Family:           {self.family}\n"
