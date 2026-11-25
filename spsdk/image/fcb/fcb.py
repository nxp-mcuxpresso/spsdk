#!/usr/bin/env python
#
# Copyright 2022-2026 NXP
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

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image.mem_type import MemoryType
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness, load_configuration, swap_bytes, value_to_bytes
from spsdk.utils.registers import Registers, RegistersPreValidationHook

logger = logging.getLogger(__name__)
UNKNOWN_FAMILY = FamilyRevision("Unknown")


class FCB(SegmentBase):
    """FCB (Flash Configuration Block) segment for NXP MCU images.

    This class represents a Flash Configuration Block that contains memory-specific
    configuration data for NXP microcontrollers. The FCB provides essential
    parameters for proper flash memory initialization and operation.

    :cvar FEATURE: Database feature identifier for FCB operations.
    :cvar TAG: Binary tag identifier for FCB segments.
    :cvar TAG_SWAPPED: Byte-swapped version of the FCB tag.
    :cvar TAG_REGISTER: Default name of the register holding the FCB tag.
    """

    FEATURE = DatabaseManager.FCB
    PRE_VALIDATION_CFG_HOOK = RegistersPreValidationHook(register_keys=["fcb_settings"])
    TAG = b"FCFB"
    TAG_SWAPPED = swap_bytes(TAG)
    TAG_REGISTER = "tag"

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
        self.tag_register: str = self.db.get_str(
            self.FEATURE, ["mem_types", self.mem_type.label, "tag_register"], self.TAG_REGISTER
        )
        self.crc_register: str | None = (
            self.db.get_str(self.FEATURE, ["mem_types", self.mem_type.label, "crc_register"], "")
            or None
        )

    @property
    def tag(self) -> bytes:
        """Get the expected FCB tag for used memory type.

        :return: Expected tag value in bytes.
        """
        return value_to_bytes(
            self.registers.find_reg(self.tag_register).get_reset_value(),
            byte_cnt=4,
            endianness=Endianness.LITTLE,
        )

    @property
    def tag_offset(self) -> int:
        """Get the offset of FCB tag for used memory type.

        :return: Offset of the tag register in bytes.
        """
        return self.registers.find_reg(self.tag_register).offset

    def calculate_crc(self) -> int:
        """Calculate the FCB checksum.

        The CRC32 MPEG2 variant is calculated over the whole FCB except the checksum field itself.

        :raises SPSDKError: The FCB of this memory type has no checksum.
        :return: Calculated checksum.
        """
        if not self.crc_register:
            raise SPSDKError(f"FCB for memory type {self.mem_type.label} has no checksum.")
        crc_reg = self.registers.find_reg(self.crc_register)
        data = self.registers.export()
        data = data[: crc_reg.offset] + data[crc_reg.offset + crc_reg.width // 8 :]
        return from_crc_algorithm(CrcAlg.CRC32_MPEG).calculate(data)

    def update_crc(self) -> None:
        """Update the FCB checksum register, if the FCB of used memory type has any."""
        if self.crc_register:
            self.registers.find_reg(self.crc_register).set_value(self.calculate_crc(), raw=True)

    def export(self) -> bytes:
        """Export FCB to binary representation with updated checksum.

        :return: Binary data of the FCB.
        """
        self.update_crc()
        return super().export()

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
        family: FamilyRevision = UNKNOWN_FAMILY,
        mem_type: MemoryType = MemoryType.FLEXSPI_NOR,
    ) -> Self:
        """Parse binary block into FCB object.

        Parses a binary data block to create an FCB (Flash Configuration Block) object.
        The method automatically detects and corrects byte order swapping if needed.

        :param binary: Binary image data to parse.
        :param offset: Offset position of FCB in the binary image.
        :param family: Target chip family revision.
        :param mem_type: Memory type used for the FCB.
        :raises SPSDKError: If binary block size is insufficient, contains invalid FCB tag
            or invalid checksum.
        :return: Parsed FCB object instance.
        """
        fcb = cls(family=family, mem_type=mem_type)
        binary = binary[offset:]
        if len(binary) < fcb.size:
            raise SPSDKError(f"Invalid input binary block size: ({len(binary)} < {fcb.size}).")
        tag_offset = fcb.tag_offset
        expected_tag = fcb.tag
        if binary[tag_offset : tag_offset + len(expected_tag)] == swap_bytes(expected_tag):
            logger.info("Swapped bytes order has been detected. Fixing the bytes order.")
            binary = swap_bytes(binary)
        fcb.registers.parse(binary)
        tag = fcb.registers.find_reg(fcb.tag_register)
        if tag.get_bytes_value() != expected_tag:
            raise SPSDKError(
                f"Tag value {tag.get_bytes_value()!r} does does not match the expected value."
            )
        if fcb.crc_register:
            crc = fcb.registers.find_reg(fcb.crc_register).get_value(raw=True)
            calculated_crc = fcb.calculate_crc()
            if crc != calculated_crc:
                raise SPSDKError(
                    f"FCB checksum 0x{crc:08X} does not match the calculated value "
                    f"0x{calculated_crc:08X}."
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
            preset = config.get("preset")
            if preset:
                fcb.apply_preset(str(preset))
            # The explicit settings are applied on top of the preset (if any)
            if "fcb_settings" in config:
                fcb.registers.load_from_config(config.get_config("fcb_settings"))
            elif not preset:
                raise SPSDKValueError("The 'fcb_settings' or 'preset' must be defined.")
        except (SPSDKError, AttributeError) as exc:
            raise SPSDKValueError(f"Cannot load FCB configuration: {exc!s}") from exc
        return fcb

    @classmethod
    def get_presets(
        cls, family: FamilyRevision, mem_type: MemoryType = MemoryType.FLEXSPI_NOR
    ) -> dict[str, dict[str, Any]]:
        """Get FCB presets for standard memories defined in the database.

        The presets are stored in a separate data file referenced by the 'presets_file' key of the
        memory type in the database. Each preset is a dictionary with a 'description' and
        'settings' with register values, which are applied on top of the reset values of the FCB
        registers.

        :param family: Chip family and revision information.
        :param mem_type: Memory type of the FCB.
        :return: Dictionary of presets, the key is the preset name.
        """
        mem_types_cfg = cls.get_memory_types_config(family)
        if "presets_file" not in mem_types_cfg.get(mem_type.label, {}):
            return {}
        presets_file = get_db(family).get_file_path(
            cls.FEATURE, ["mem_types", mem_type.label, "presets_file"]
        )
        return dict(load_configuration(presets_file))

    def apply_preset(self, preset: str) -> None:
        """Apply FCB preset of a standard memory to the FCB registers.

        :param preset: Name of the preset from the database.
        :raises SPSDKValueError: The preset is not defined for the family and memory type.
        """
        presets = self.get_presets(self.family, self.mem_type)
        if preset not in presets:
            raise SPSDKValueError(
                f"Unknown FCB preset '{preset}' for {self.family} and {self.mem_type.label}. "
                f"Available presets: {', '.join(presets) or 'none'}"
            )
        self.registers.load_from_config(Config(presets[preset]["settings"]))

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
            presets = cls.get_presets(fcb_obj.family, mem_type)
            if presets:
                # The preset can be used instead of, or together with, the FCB settings
                sch_preset = sch_cfg["fcb"]["properties"]["preset"]
                sch_preset["enum"] = list(presets)
                sch_preset["description"] += "".join(
                    f"\n - {name}: {preset['description']}" for name, preset in presets.items()
                )
                sch_cfg["fcb"].pop("required")
                sch_cfg["fcb"]["anyOf"] = [{"required": ["fcb_settings"]}, {"required": ["preset"]}]
            else:
                sch_cfg["fcb"]["properties"].pop("preset")
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
        cls,
        family: FamilyRevision,
        mem_type: MemoryType = MemoryType.FLEXSPI_NOR,
        preset: str | None = None,
    ) -> str:
        """Get configuration template for selected family and memory type.

        Generates a configuration template for FCB (Flash Configuration Block) based on
        the specified family revision and memory type parameters. If a preset is specified,
        the template is filled by the values of the preset.

        :param family: Family revision specification for target MCU.
        :param mem_type: Memory type to generate configuration for.
        :param preset: Optional name of the FCB preset used to fill the template.
        :return: Template string of FCB Block configuration.
        """
        if preset:
            fcb = cls(family=family, mem_type=mem_type)
            fcb.apply_preset(preset)
            return fcb.get_config_yaml()
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
