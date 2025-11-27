#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Memory configuration management utilities.

This module provides functionality for handling memory configuration options,
including flash configuration option words and memory interface management
across NXP MCU portfolio.
"""


import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_common_data_file_path, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, get_device, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.strict_registers import StrictRegisters

logger = logging.getLogger(__name__)


class SPSDKUnsupportedInterface(SPSDKError):
    """SPSDK exception for unsupported memory interface operations.

    This exception is raised when attempting to use a memory interface that is not
    supported by the current SPSDK configuration or hardware target.
    """


@dataclass
class MemoryInterface:
    """Memory interface representation for SPSDK memory configuration.

    This class represents a memory interface with its associated option words and testing status.
    It provides functionality to manage and format memory interface configuration data used
    in SPSDK memory configuration operations.
    """

    name: str
    option_words: list = field(default_factory=list)
    tested: bool = False

    def get_option_words_string(self) -> str:
        """Get option words in string format.

        The method converts the option words to a formatted string representation
        with each option word displayed in hexadecimal format.

        :return: String containing option words in format "Opt0: 0xXXXXXXXX, Opt1: 0xXXXXXXXX".
        """
        option_words_str = f"Opt0: 0x{self.option_words[0]:08X}"
        for ow_i, ow in enumerate(self.option_words[1:]):
            option_words_str += f", Opt{ow_i+1}: 0x{ow:08X}"
        return option_words_str


@dataclass
class Memory:
    """Memory configuration representation for SPSDK operations.

    This class represents a memory device with its properties and supported interfaces,
    providing methods to query and access available communication interfaces.
    """

    name: str
    type: str  # Memory type [nor, nand, sd]
    manufacturer: str
    interfaces: list[MemoryInterface]

    def get_interface(self, interface: str) -> MemoryInterface:
        """Get interface by its name.

        :param interface: Interface name to search for.
        :raises SPSDKValueError: Interface is not presented in memory.
        :return: Memory interface object.
        """
        for x in self.interfaces:
            if x.name == interface:
                return x
        raise SPSDKValueError(f"The interface {interface} is not supported by {self.name} chip.")

    def has_interface(self, interface: str) -> bool:
        """Check if memory has mentioned interface.

        :param interface: Interface name to check for existence.
        :return: True if interface exists, False otherwise.
        """
        for x in self.interfaces:
            if x.name == interface:
                return True
        return False


class MemoryConfig(FeatureBaseClass):
    """SPSDK Memory Configuration Manager.

    This class manages memory configuration for NXP MCU peripherals, providing
    functionality to configure memory interfaces, validate settings, and generate
    configuration data for various memory types across the supported MCU families.

    :cvar FEATURE: Database feature identifier for memory configuration.
    :cvar PERIPHERALS: List of supported peripheral names across all families.
    :cvar SUPPORTS_FCB_CREATION: List of region numbers that support FCB creation.
    """

    FEATURE = DatabaseManager.MEMCFG
    # Supported peripherals and their region numbers
    PERIPHERALS: list[str] = list(
        DatabaseManager().db.get_defaults(DatabaseManager.MEMCFG)["peripherals"].keys()
    )
    SUPPORTS_FCB_CREATION = [9]

    def __init__(
        self,
        family: FamilyRevision,
        peripheral: str,
        interface: Optional[str] = None,
    ) -> None:
        """Initialize memory configuration class.

        Initialize the memory configuration for a specific chip family and peripheral,
        setting up registers and validating the memory interface.

        :param family: Chip family and revision information.
        :param peripheral: Name of the peripheral to configure.
        :param interface: Memory interface to use. If None, uses the first supported interface.
        :raises SPSDKValueError: When the peripheral is not supported by the chip family.
        :raises SPSDKUnsupportedInterface: When the interface is not supported for the given
            family and peripheral combination.
        """
        self.family = family
        self.db = get_db(family)
        if peripheral not in self.get_supported_peripherals(self.family):
            raise SPSDKValueError(f"The {peripheral} is not supported by {self.family}")
        self.peripheral = peripheral
        self.regs = StrictRegisters(
            family=self.family,
            feature=DatabaseManager.MEMCFG,
            base_key=["peripherals", peripheral],
            base_endianness=Endianness.LITTLE,
        )
        self.interface = interface or self.supported_interfaces[0]
        if self.interface not in self.supported_interfaces:
            raise SPSDKUnsupportedInterface(
                f"Interface '{self.interface}' is not supported for family '{family}' peripheral '{peripheral}'"
            )

    def __repr__(self) -> str:
        """Get string representation of the memory configuration object.

        :return: String containing family and peripheral information.
        """
        return f"Memory configuration for {self.family}, {self.peripheral}"

    def __str__(self) -> str:
        """Get string representation of the memory configuration.

        Provides a detailed string representation including the interface type and option words
        used in the memory configuration.

        :return: String representation with interface and option words information.
        """
        return (
            self.__repr__()
            + f"\n Used interface is {self.interface} and option words are {self.option_words}"
        )

    @property
    def option_words(self) -> list[int]:
        """Get option words from memory configuration registers.

        Retrieves the values of option words by iterating through the available
        registers up to the specified count limit.

        :return: List of option word values as integers.
        """
        ret: list[int] = []
        count_to_export = self.option_words_count
        for i, reg in enumerate(self.regs.get_registers()):
            if i >= count_to_export:
                break
            ret.append(reg.get_value())
        return ret

    @property
    def option_words_count(self) -> int:
        """Get current count of option words.

        Determines the number of option words based on the peripheral's configuration rule.
        The count is calculated using different strategies depending on the rule type:
        - "All": Returns total number of registers
        - "OptionSize": Returns 1 plus the OptionSize bitfield value
        - "AcTimingMode": Returns all registers if UserDefined, otherwise 1

        :raises SPSDKValueError: When an unsupported rule is encountered for determining
            option word count.
        :return: Number of option words for the current peripheral configuration.
        """
        rule = self.db.get_str(
            DatabaseManager.MEMCFG, ["peripherals", self.peripheral, "ow_counts_rule"]
        )
        if rule == "All":
            return len(self.regs.get_registers())

        if rule == "OptionSize":
            return 1 + self.regs.get_registers()[0].find_bitfield("OptionSize").get_value()

        if rule == "AcTimingMode":
            if (
                self.regs.get_registers()[0].find_bitfield("AcTimingMode").get_enum_value()
                == "UserDefined"
            ):
                return len(self.regs.get_registers())
            return 1
        raise SPSDKValueError("Unsupported rule to determine the count of Option words")

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get validation schema for the object.

        The method retrieves validation schemas based on the object's family, peripheral,
        and interface properties by delegating to the static get_validation_schemas method.

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.peripheral, self.interface)

    @classmethod
    def get_validation_schemas(
        cls,
        family: FamilyRevision,
        peripheral: str = "Unknown",
        interface: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Create the validation schema for one peripheral.

        The method builds validation schemas by combining family, base configuration, and settings
        schemas. It updates the schemas with supported peripherals and interfaces for the given
        family and configures the settings schema using StrictRegisters.

        :param family: The MCU family revision identifier.
        :param peripheral: Name of the peripheral to create validation schema for.
        :param interface: Memory interface type, optional parameter.
        :return: List containing family, base, and settings validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.MEMCFG)
        sch_family = get_schema_file("general")["family"]

        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )
        sch_family["main_title"] = f"Option Words Configuration for {family}, {peripheral}."
        sch_family["note"] = "Note for settings:\n" + StrictRegisters.TEMPLATE_NOTE

        memcfg = cls(family=family, peripheral=peripheral, interface=interface)
        sch_cfg["base"]["properties"]["peripheral"]["template_value"] = memcfg.peripheral
        sch_cfg["base"]["properties"]["peripheral"]["enum"] = memcfg.get_supported_peripherals(
            family
        )
        sch_cfg["base"]["properties"]["interface"]["template_value"] = memcfg.interface
        sch_cfg["base"]["properties"]["interface"]["enum"] = cls.get_supported_interfaces(
            family, peripheral
        )

        sch_cfg["settings"]["properties"]["settings"] = StrictRegisters(
            family, feature=cls.FEATURE, base_key=["peripherals", peripheral]
        ).get_validation_schema()

        return [sch_family, sch_cfg["base"], sch_cfg["settings"]]

    @classmethod
    def get_config_template(
        cls,
        family: FamilyRevision,
        peripheral: str = "Unknown",
        interface: Optional[str] = None,
    ) -> str:
        """Get feature configuration template.

        Generates a configuration template for the specified MCU family and peripheral,
        which can be used as a starting point for memory configuration.

        :param family: The MCU family name and revision information.
        :param peripheral: Name of the peripheral to generate template for.
        :param interface: Memory interface type, if applicable.
        :return: Template file string representation.
        """
        schemas = cls.get_validation_schemas(family, peripheral=peripheral, interface=interface)
        return cls._get_config_template(family, schemas)

    @classmethod
    def parse(  # type: ignore# type: ignore # pylint: disable=arguments-differ
        cls,
        data: bytes,
        family: FamilyRevision,
        peripheral: str,
        interface: Optional[str] = None,
    ) -> Self:
        """Parse the option words to configuration.

        Creates a new instance of the class and parses the provided option words data
        into the internal registers structure.

        :param data: Option words in bytes to be parsed.
        :param family: Chip family revision information.
        :param peripheral: Name of the peripheral device.
        :param interface: Memory interface specification, defaults to None.
        :return: New instance with parsed configuration data.
        """
        ret = cls(family=family, peripheral=peripheral, interface=interface)
        ret.regs.parse(data)
        return ret

    @staticmethod
    def option_words_to_bytes(option_words: list[int]) -> bytes:
        """Convert option words to bytes.

        The method converts a list of integer option words into a byte sequence
        using little-endian byte order, with each option word represented as 4 bytes.

        :param option_words: List of integer option words to convert.
        :return: Byte sequence containing the converted option words.
        """
        ow_bytes = bytes()
        for ow in option_words:
            ow_bytes += ow.to_bytes(4, Endianness.LITTLE.value)
        return ow_bytes

    def export(self) -> bytes:
        """Export option words to bytes.

        :return: Binary representation of the option words.
        """
        return self.regs.export()

    def get_config(self, data_path: str = "./") -> Config:
        """Create memory configuration object.

        The method generates a configuration dictionary containing family information,
        peripheral settings, interface details, and register configurations up to the
        maximum option words count.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration object with memory settings.
        """
        ret = Config()
        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["peripheral"] = self.peripheral
        ret["interface"] = self.interface or "Unknown"
        settings_all = self.regs.get_config()
        max_cnt = self.option_words_count
        settings = {}
        for i, reg in enumerate(self.regs.get_registers()):
            if i >= max_cnt:
                break
            settings[reg.name] = settings_all[reg.name]

        ret["settings"] = settings
        return ret

    @property
    def supported_interfaces(self) -> list[str]:
        """Get list of supported interfaces for the current family and peripheral.

        :return: List of interface names supported by the current memory configuration.
        """
        return self.get_supported_interfaces(self.family, self.peripheral)

    @staticmethod
    def get_supported_peripherals(family: FamilyRevision) -> list[str]:
        """Get list of supported peripherals by the family.

        The method retrieves all peripherals that have at least one instance configured
        for the specified family from the memory configuration database.

        :param family: Family revision to get supported peripherals for.
        :return: List of peripheral names that are supported by the family.
        """
        ret = []
        for peripheral, settings in (
            get_db(family).get_dict(DatabaseManager.MEMCFG, "peripherals").items()
        ):
            if len(settings["instances"]):
                ret.append(peripheral)
        return ret

    @staticmethod
    def get_supported_interfaces(family: FamilyRevision, peripheral: str) -> list[str]:
        """Get list of supported interfaces by the peripheral for the family.

        Retrieves the available communication interfaces that can be used with a specific
        peripheral on the given MCU family.

        :param family: MCU family and revision specification.
        :param peripheral: Name of the peripheral to query interfaces for.
        :return: List of supported interface names for the specified peripheral.
        """
        peripherals = get_db(family).get_dict(DatabaseManager.MEMCFG, "peripherals")
        peripheral_data: dict[str, list[str]] = peripherals.get(peripheral, {})

        return peripheral_data.get("interfaces", [])

    @staticmethod
    def get_peripheral_instances(family: FamilyRevision, peripheral: str) -> list[int]:
        """Get peripheral instances for a specific family and peripheral type.

        Retrieves the list of available instances for a given peripheral from the memory
        configuration database.

        :param family: Target MCU family and revision information.
        :param peripheral: Name of the peripheral to get instances for.
        :return: List of peripheral instance numbers available for the specified family and peripheral.
        """
        return get_db(family).get_list(
            DatabaseManager.MEMCFG,
            ["peripherals", peripheral, "instances"],
            [],
        )

    @staticmethod
    def get_validation_schemas_basic() -> list[dict[str, Any]]:
        """Get validation schemas for MemCfg class basic configuration.

        The method retrieves and combines validation schemas for family configuration
        and base memory configuration settings. It updates the family schema with
        currently supported families from MemoryConfig.

        :return: List containing family and base configuration validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.MEMCFG)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], MemoryConfig.get_supported_families()
        )
        return [sch_family, sch_cfg["base"]]

    @staticmethod
    def option_words_to_string(option_words: list[int]) -> str:
        """Convert option words list to formatted hexadecimal string representation.

        The method takes a list of integer option words and formats them as a comma-separated
        string of hexadecimal values with 0x prefix and 8-digit zero-padding.

        :param option_words: List of integer option words to be converted to string format.
        :return: Comma-separated string of hexadecimal option words (e.g., "0x12345678, 0xABCDEF00").
        """
        option_words_str = f"0x{option_words[0]:08X}"
        for ow in option_words[1:]:
            option_words_str += f", 0x{ow:08X}"
        return option_words_str

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method validates the provided configuration against basic schemas and creates
        a memory configuration instance to retrieve the appropriate validation schemas.

        :param config: Valid configuration object containing family and peripheral settings
        :return: List of validation schema dictionaries for the memory configuration
        :raises SPSDKError: If configuration validation fails
        """
        config.check(cls.get_validation_schemas_basic())
        memcfg = cls(
            family=FamilyRevision.load_from_config(config), peripheral=config["peripheral"]
        )
        return memcfg._get_validation_schemas()

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load memory configuration object from configuration.

        The method creates a new memory configuration instance by extracting family,
        peripheral, and interface information from the provided configuration, then
        loads register settings into the configuration object.

        :param config: Configuration dictionary containing memory setup parameters.
        :return: Initialized memory configuration object with loaded settings.
        """
        family = FamilyRevision.load_from_config(config)
        peripheral = config.get_str("peripheral")
        interface = config.get_str("interface")
        ret = cls(family=family, peripheral=peripheral, interface=interface)
        ret.regs.load_from_config(config.get_config("settings"))
        return ret

    def create_blhost_batch_config(
        self,
        instance: Optional[int] = None,
        fcb_output_name: Optional[str] = None,
        secure_addresses: bool = False,
    ) -> str:
        """Create BLHOST script that configures memory.

        Optionally the script can force creation of FCB on chip and read it back.

        :param instance: Optional peripheral instance number for runtime switching
        :param fcb_output_name: Name of the generated FCB block file for readback
        :param secure_addresses: Use secure addresses instead of normal addresses
        :raises SPSDKValueError: Invalid instance or unsupported runtime instance switch
        :raises SPSDKValueError: Missing memory block description for FCB generation
        :return: BLHOST batch script content that configures the external memory
        """
        comm_address = self.db.get_int(DatabaseManager.COMM_BUFFER, "address")
        mem_region = self.db.get_int(
            DatabaseManager.MEMCFG,
            ["peripherals", self.peripheral, "region_number"],
        )
        ret = (
            "# BLHOST configure memory programming script\n"
            f"# Generated by SPSDK NXPMEMCFG tool\n"
            f"# Chip: {self.family}\n"
            f"# Peripheral: {self.peripheral}\n"
            f"# Instance: {instance if instance is not None else 'N/A'}\n\n"
        )
        instances = self.db.get_list(
            DatabaseManager.MEMCFG, ["peripherals", self.peripheral, "instances"]
        )
        runtime_instance = self.db.get_bool(
            DatabaseManager.MEMCFG, ["peripherals", self.peripheral, "runtime_instance"], False
        )
        if instance is not None and ((instance not in instances) or not runtime_instance):
            raise SPSDKValueError(
                f"Unsupported runtime instance switch for {self.family}:{self.peripheral}\n"
                "Possible reasons:\n"
                f"Instance {instance} not in supported instances{instances}\n"
                f"Peripheral {self.peripheral} doesn't support runtime switch of instance"
            )

        if (instance is None) and len(instances) > 1 and runtime_instance:
            raise SPSDKValueError(
                f"Unspecified instance for {self.family}:{self.peripheral}."
                "The -ix option is mandatory for devices with more than one instance"
            )

        if instance is not None:  # and switch_instances:
            # Switch instance of peripheral in runtime
            switch_opt_word = 0xCF90_0000 + (instance & 0xF_FFFF)
            ret += f"# Switch the instance of the peripheral to {instance}:\n"
            ret += f"fill-memory 0x{comm_address:08X} 4 0x{switch_opt_word:08X}\n"
            ret += f"configure-memory {mem_region} 0x{comm_address:08X}\n\n"

        ret += "# Configure memory:\n"
        for i, opt in enumerate(self.option_words):
            ret += f"# Option word {i}: 0x{opt:08X}\n"
            ret += f"fill-memory 0x{comm_address + i*4:08X} 4 0x{opt:08X}\n"
        ret += f"configure-memory {mem_region} 0x{comm_address:08X}\n"

        if fcb_output_name:
            fcb_output_name = fcb_output_name.replace("\\", "/")

            if mem_region not in self.SUPPORTS_FCB_CREATION:
                ret += "\n#FCB read back is supported just only for FlexSPI NOR configuration"
                logger.warning("FCB read back is supported just only for FlexSPI NOR configuration")
                return ret
            dev = get_device(self.family)
            mem_block = self.peripheral.split("_")[0]
            try:
                mem = dev.info.memory_map.get_memory(
                    block_name=mem_block,
                    instance=instance,
                    secure=secure_addresses if secure_addresses else None,
                )

            except SPSDKError as exc:
                raise SPSDKValueError(
                    f"Cannot create BLHOST script with FCB generation because of missing memory block"
                    f" '{mem_block}' description"
                ) from exc

            fcb_offset = self.db.get_int(
                DatabaseManager.BOOTABLE_IMAGE, ["mem_types", self.peripheral, "segments", "fcb"]
            )
            logger.warning(
                "FCB block read back script has been generated. "
                "Be aware that s 4KB block at base address will be erased to avoid"
                " cumulative write!"
            )
            ret += "\n# Script to erase FCB location, create FCB and read back a FCB block:\n"
            ret += f"flash-erase-region 0x{mem.base_address:08X} 0x1000\n"
            ret += f"fill-memory 0x{comm_address:08X} 4 0xF000000F\n"
            ret += f"configure-memory {mem_region} 0x{comm_address:08X}\n"
            ret += f"read-memory 0x{mem.base_address+fcb_offset:08X} 0x200 {fcb_output_name}\n"

        return ret

    @staticmethod
    def get_peripheral_cnt(family: FamilyRevision, peripheral: str) -> int:
        """Get count of peripheral instances for specified family and peripheral type.

        :param family: Target MCU family and revision information.
        :param peripheral: Name of the peripheral type to count instances for.
        :return: Number of available instances for the specified peripheral.
        """
        return len(
            get_db(family).get_list(
                DatabaseManager.MEMCFG,
                ["peripherals", peripheral, "instances"],
                [],
            )
        )

    @staticmethod
    def _find_family_for_peripheral(peripheral: str) -> Optional[FamilyRevision]:
        """Find a family that supports the given peripheral.

        This method searches through all supported families to find one that includes
        the specified peripheral in its supported peripherals list.

        :param peripheral: The peripheral name to search for.
        :return: A family that supports the peripheral, or None if not found.
        """
        for supported_family in MemoryConfig.get_supported_families():
            if peripheral in MemoryConfig.get_supported_peripherals(supported_family):
                logger.debug(
                    f"Found family {supported_family} that supports peripheral {peripheral}"
                )
                return supported_family
        return None

    @staticmethod
    def _get_memories_for_peripheral_without_family(peripheral: str) -> list[Memory]:
        """Get memories for a peripheral when no family is available.

        This method serves as a fallback when family information is not provided. It attempts to
        determine the appropriate memory configuration from the default database based on the
        peripheral type, or returns all known memories if no specific configuration is found.

        :param peripheral: The peripheral name to get memory configuration for.
        :return: List of Memory objects compatible with the specified peripheral.
        """
        logger.warning(
            f"No family found that supports peripheral {peripheral}, returning all memories"
        )
        # Try to determine memory type from default database
        p_db = DatabaseManager().db.get_defaults(DatabaseManager.MEMCFG)["peripherals"]
        if peripheral in p_db:
            mem_type = p_db[peripheral]["mem_type"]
            interfaces = p_db[peripheral]["interfaces"]
            return MemoryConfig.get_known_memories(mem_type=mem_type, interfaces=interfaces)
        return MemoryConfig.get_known_memories()

    @staticmethod
    def _get_peripherals_for_family(family: FamilyRevision, peripheral: Optional[str]) -> list[str]:
        """Get list of peripherals for a family.

        The method returns either a filtered list containing only the specified peripheral
        or all available peripherals for the given family that have a non-zero count.

        :param family: The family revision to get peripherals for.
        :param peripheral: Optional specific peripheral name to filter for.
        :return: List of peripheral names available for the family.
        """
        if peripheral:
            return [peripheral]
        return [p for p in MemoryConfig.PERIPHERALS if MemoryConfig.get_peripheral_cnt(family, p)]

    @staticmethod
    def _get_memory_types_and_interfaces(peripherals: list[str], p_db: dict) -> dict[str, set]:
        """Get memory types and interfaces for the given peripherals.

        This method processes a list of peripherals and extracts their memory types and
        corresponding interfaces from the peripherals database. It aggregates interfaces
        for each memory type, combining them when multiple peripherals share the same
        memory type.

        :param peripherals: List of peripheral names to process.
        :param p_db: Peripherals database containing memory type and interface information.
        :return: Dictionary mapping memory types to sets of their available interfaces.
        """
        wanted_mem_types: dict[str, set] = {}
        for p in peripherals:
            if p not in p_db:
                logger.error(f"The peripheral '{p}' is NOT supported!")
                continue

            mt = p_db[p]["mem_type"]
            mi = p_db[p]["interfaces"]
            if mt in wanted_mem_types:
                wanted_mem_types[mt].update(set(mi))
            else:
                wanted_mem_types[mt] = set(mi)
        return wanted_mem_types

    @staticmethod
    def _validate_memory_interfaces(
        memory: Memory, validation_family: FamilyRevision, peripheral: str, memory_type: str
    ) -> list[MemoryInterface]:
        """Validate memory interfaces against a family revision.

        The method validates each interface in the memory by attempting to parse its option words
        using the specified family, peripheral, and interface configuration. Only interfaces that
        pass validation are included in the returned list.

        :param memory: The memory object containing interfaces to validate.
        :param validation_family: The family revision to validate against.
        :param peripheral: The peripheral name to use for validation.
        :param memory_type: The memory type identifier.
        :return: List of validated memory interfaces that passed validation.
        """
        validated_interfaces = []
        for interface in memory.interfaces:
            try:
                # Convert option words to bytes
                option_words_bytes = MemoryConfig.option_words_to_bytes(interface.option_words)

                # Try to parse the option words
                MemoryConfig.parse(
                    data=option_words_bytes,
                    family=validation_family,
                    peripheral=peripheral,
                    interface=interface.name,
                )
                validated_interfaces.append(interface)
            except Exception as e:
                logger.debug(
                    f"Failed to validate option words for {memory.name} with {interface.name}: {str(e)}"
                )
        return validated_interfaces

    @staticmethod
    def get_known_peripheral_memories(
        family: Optional[FamilyRevision],
        peripheral: Optional[str] = None,
        validate_option_words: bool = True,
    ) -> list[Memory]:
        """Get all known supported memory configurations.

        This method retrieves memory configurations based on the specified family and peripheral.
        It can optionally validate that option words for the memories can be properly parsed.

        :param family: The optional chip family to filter memories for.
        :param peripheral: Restrict results just for this one peripheral if defined.
        :param validate_option_words: If True, validate that option words can be parsed.
        :raises SPSDKValueError: In case the family does not support external memories.
        :return: List of supported memory configurations.
        """
        # Early return for simple case
        if not family and not peripheral:
            return MemoryConfig.get_known_memories()

        # Try to find a family if only peripheral is specified
        if peripheral and not family:
            family = MemoryConfig._find_family_for_peripheral(peripheral)
            if not family:
                return MemoryConfig._get_memories_for_peripheral_without_family(peripheral)
        assert family is not None  # The family is certainly not None at this point
        peripherals = MemoryConfig._get_peripherals_for_family(family, peripheral)

        # Get database for the family
        p_db = get_db(family).get_dict(DatabaseManager.MEMCFG, "peripherals")

        # Get memory types and interfaces
        wanted_mem_types = MemoryConfig._get_memory_types_and_interfaces(peripherals, p_db)

        # Process each memory type
        ret = []
        for mt, mi in wanted_mem_types.items():
            memories = MemoryConfig.get_known_memories(mt, list(mi))

            # Skip validation if not requested or no peripheral specified
            if not validate_option_words or not peripheral:
                ret.extend(memories)
                continue

            # Find a family for validation if needed
            validation_family = family
            if not validation_family:
                try:
                    validation_family = MemoryConfig.get_supported_families()[0]
                    logger.debug(f"Using {validation_family} for option words validation")
                except IndexError:
                    # If no families are available, skip validation
                    logger.warning(
                        "No families available for option words validation, skipping validation"
                    )
                    ret.extend(memories)
                    continue

            # Validate memories
            validated_memories = []
            for memory in memories:
                peripheral_name = peripherals[0] if len(peripherals) == 1 else f"{mt}_based"
                validated_interfaces = MemoryConfig._validate_memory_interfaces(
                    memory, validation_family, peripheral_name, mt
                )

                # Add memory with validated interfaces
                if validated_interfaces:
                    validated_memory = Memory(
                        name=memory.name,
                        type=memory.type,
                        manufacturer=memory.manufacturer,
                        interfaces=validated_interfaces,
                    )
                    validated_memories.append(validated_memory)
                else:
                    logger.debug(f"No valid interfaces found for {memory.name}")

            ret.extend(validated_memories)

        return ret

    @staticmethod
    def get_known_memories(
        mem_type: Optional[str] = None, interfaces: Optional[list[str]] = None
    ) -> list[Memory]:
        """Get all known supported memory configurations.

        Loads memory configuration data from the database and filters based on specified
        memory type and interfaces.

        :param mem_type: Restrict results just for this one memory type if defined.
        :param interfaces: Restrict results just for mentioned memory interfaces if defined.
        :return: List of Memory objects containing supported memory configurations.
        """
        chips_db: dict[str, dict[str, Any]] = DatabaseManager().db.load_db_cfg_file(
            get_common_data_file_path(os.path.join("memcfg", "memcfg_data.yaml"))
        )
        ret = []

        for chip_name, chip_data in chips_db.items():
            assert isinstance(chip_data, dict)
            mt: str = chip_data["type"]
            if mem_type and mem_type != mt:
                continue

            mem_interfaces: list[MemoryInterface] = []
            src_interfaces: dict[str, dict] = chip_data.get("interfaces", {})
            for i_name, i_data in src_interfaces.items():
                if interfaces and i_name not in interfaces:
                    continue
                option_words: list[int] = i_data["option_words"]
                tested: bool = bool(i_data.get("tested", False))
                mem_interfaces.append(
                    MemoryInterface(name=i_name, option_words=option_words, tested=tested)
                )
            if not len(mem_interfaces):
                continue

            ret.append(
                Memory(
                    name=chip_name,
                    type=mt,
                    manufacturer=chip_data.get("manufacturer", "N/A"),
                    interfaces=mem_interfaces,
                )
            )

        return ret

    @staticmethod
    def get_known_chip_memory(chip_name: str) -> Memory:
        """Get Memory for one chip from database.

        Retrieves the Memory object for a specific chip by searching through the known
        memory configurations in the database.

        :param chip_name: Name of the chip to search for in the memory database.
        :raises SPSDKValueError: If the specified chip name is not found in database.
        :return: Memory object containing configuration for the specified chip.
        """
        for memory in MemoryConfig.get_known_memories():
            if memory.name == chip_name:
                return memory

        raise SPSDKValueError(f"Unknown flash memory chip name: {chip_name}")
