#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Flash Configuration Block (FCB) management utilities.

This module provides functionality for handling Flash Configuration Blocks,
which contain essential flash memory configuration parameters for NXP MCUs.
The FCB class enables creation, validation, and manipulation of flash
configuration data required for proper boot sequence initialization.
"""


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
from spsdk.utils.registers import Registers, RegistersPreValidationHook

logger = logging.getLogger(__name__)


class FCB(SegmentBase):
    """FCB (Flash Configuration Block) segment for NXP MCU images.

    This class represents a Flash Configuration Block that contains memory-specific
    configuration data for NXP microcontrollers. The FCB provides essential
    parameters for proper flash memory initialization and operation.

    :cvar FEATURE: Database feature identifier for FCB operations.
    :cvar TAG: Binary tag identifier for FCB segments.
    :cvar TAG_SWAPPED: Byte-swapped version of the FCB tag.
    """

    FEATURE = DatabaseManager.FCB
    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["fcb_settings"])
    TAG = b"FCFB"
    TAG_SWAPPED = swap_bytes(TAG)

    def __init__(self, family: FamilyRevision, mem_type: MemoryType) -> None:
        """FCB Constructor.

        Initialize FCB (Flash Configuration Block) for specified chip family and memory type.

        :param family: Chip family and revision information.
        :param mem_type: Memory type to be used for FCB configuration.
        :raises SPSDKValueError: Unsupported family or memory type for the given family.
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
    def size(self) -> int:
        """Get the size of the segment in bytes.

        :return: The segment size in bytes.
        """
        return self.registers.size

    @property
    def registers(self) -> Registers:
        """Get the registers of the FCB segment.

        :return: Registers object containing the FCB configuration registers.
        """
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

        Parses a binary data block to create an FCB (Flash Configuration Block) object.
        The method automatically detects and corrects byte order swapping if needed.

        :param binary: Binary image data to parse.
        :param offset: Offset position of FCB in the binary image.
        :param family: Target chip family revision.
        :param mem_type: Memory type used for the FCB.
        :raises SPSDKError: If binary block size is insufficient or contains invalid FCB tag.
        :return: Parsed FCB object instance.
        """
        fcb = cls(family=family, mem_type=mem_type)
        if len(binary[offset:]) < fcb.size:
            raise SPSDKError(
                f"Invalid input binary block size: ({len(binary[offset:])} < {fcb.size})."
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

        Creates and initializes a Flexible Configuration Block (FCB) object from the provided
        configuration data, including family revision, memory type, and FCB-specific settings.

        :param config: Configuration dictionary containing FCB parameters.
        :raises SPSDKValueError: Invalid configuration data or missing required parameters.
        :return: Initialized FCB object with loaded configuration settings.
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

        The method generates a configuration dictionary containing family information, revision,
        memory type, and FCB register settings that can be used for FCB reconstruction.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration object with FCB settings.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["type"] = self.mem_type.label
        config["fcb_settings"] = dict(self.registers.get_config())
        return config

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get validation schema for the object.

        The method retrieves validation schemas based on the object's family and memory type
        properties using the class method get_validation_schemas.

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.mem_type)

    @classmethod
    def get_validation_schemas(
        cls, family: FamilyRevision, mem_type: MemoryType = MemoryType.FLEXSPI_NOR
    ) -> list[dict[str, Any]]:
        """Create the validation schema for Flash Configuration Block.

        The method generates validation schemas for FCB configuration based on the specified
        family and memory type. It combines family-specific settings with memory type
        configurations and FCB register schemas.

        :param family: Family description specifying the target MCU family.
        :param mem_type: Used memory type for the FCB configuration.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas containing family, memory type, and FCB schemas.
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
        """Get validation schemas based on configuration.

        This method validates the basic configuration, extracts family and memory type
        information, and returns the appropriate validation schemas for the FCB.

        :param config: Configuration object containing family and memory type settings
        :return: List of validation schema dictionaries for the specified configuration
        :raises SPSDKError: Invalid configuration or unsupported family/memory type combination
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config["type"])
        return cls.get_validation_schemas(family, mem_type)

    @staticmethod
    def get_validation_schemas_basic() -> list[dict[str, Any]]:
        """Create the validation schema for FCB supported families.

        The method generates validation schemas by combining family-specific schema with
        memory type schema, filtering only for families supported by FCB.

        :return: List containing family validation schema and memory type schema for FCB.
        """
        sch_cfg = get_schema_file(DatabaseManager.FCB)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], FCB.get_supported_families())
        return [sch_family, sch_cfg["memory_type"]]

    @classmethod
    def get_config_template(
        cls, family: FamilyRevision, mem_type: MemoryType = MemoryType.FLEXSPI_NOR
    ) -> str:
        """Get configuration template for selected family and memory type.

        Generates a configuration template for FCB (Flash Configuration Block) based on
        the specified family revision and memory type parameters.

        :param family: Family revision specification for target MCU.
        :param mem_type: Memory type to generate configuration for.
        :return: Template string of FCB Block configuration.
        """
        schemas = cls.get_validation_schemas(family, mem_type)
        return cls._get_config_template(family, schemas)

    def __repr__(self) -> str:
        """Return string representation of FCB segment.

        Provides a human-readable string representation showing the memory type
        description of the FCB (Flash Configuration Block) segment.

        :return: String representation containing FCB segment and memory type description.
        """
        return f"FCB Segment, memory type: {self.mem_type.description}"

    def __str__(self) -> str:
        """Get string representation of FCB segment.

        Provides a formatted string containing the FCB segment information including
        family and memory type details.

        :return: Formatted string representation of the FCB segment.
        """
        return (
            "FCB Segment:\n"
            f" Family:           {self.family}\n"
            f" Memory type:      {self.mem_type.description}\n"
        )
