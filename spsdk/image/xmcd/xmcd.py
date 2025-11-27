#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK External Memory Configuration Data (XMCD) management utilities.

This module provides functionality for creating, parsing, and managing XMCD blocks
used to configure external memory interfaces in NXP MCUs. It includes support for
different configuration block types and CRC validation.
"""

import logging
from copy import deepcopy
from typing import Any, Optional

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.fuses.fuses import FuseScript
from spsdk.image.mem_type import MemoryType
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.exceptions import SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.family import FamilyRevision, get_db, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)


class ConfigurationBlockType(SpsdkEnum):
    """XMCD configuration block type enumeration.

    Defines the supported types of configuration blocks for XMCD (External Memory
    Configuration Data) including simplified and full configuration options.
    """

    SIMPLIFIED = (0, "simplified", "Simplified configuration")
    FULL = (1, "full", "Full configuration")


MEMORY_INTERFACE_TO_VALUE: dict[MemoryType, int] = {
    MemoryType.FLEXSPI_RAM: 0,
    MemoryType.XSPI_RAM: 0,
    MemoryType.SEMC_SDRAM: 1,
}


class XMCDHeader:
    """External Memory Configuration Data Header.

    This class manages the header section of XMCD (External Memory Configuration Data)
    structures, providing configuration and validation for external memory interfaces
    across NXP MCU families.

    :cvar TAG: XMCD header identification tag (0x0C).
    """

    TAG = 0x0C

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize the XMCD Header.

        Creates a new XMCD header instance with family-specific register configuration
        for external memory configuration data.

        :param family: Target MCU family and revision information.
        :raises SPSDKError: When register configuration cannot be loaded for the family.
        """
        self.family = family
        self.registers = Registers(
            family=family,
            feature=DatabaseManager.XMCD,
            base_key="header",
            base_endianness=Endianness.LITTLE,
        )
        self._header_reg = self.registers.find_reg("header")

    @property
    def size(self) -> int:
        """Get the size of the XMCD header.

        :return: Number of registers in the XMCD header.
        """
        return len(self.registers)

    @property
    def mem_type(self) -> MemoryType:
        """Get memory type from XMCD configuration.

        Retrieves the memory interface type from the header register and maps it to the
        corresponding supported memory type enumeration value.

        :raises SPSDKValueError: When memory type index is not supported.
        :return: Memory type enumeration value.
        """
        mem_type = self._header_reg.find_bitfield("memoryInterface").get_value()
        for sup_mem_type in self.supported_mem_types:
            if MEMORY_INTERFACE_TO_VALUE[sup_mem_type] == mem_type:
                return sup_mem_type
        raise SPSDKValueError(f"Memory type with index {mem_type} is not supported")

    @mem_type.setter
    def mem_type(self, value: MemoryType) -> None:
        """Set the memory type for the XMCD configuration.

        This method validates that the provided memory type is supported and updates
        the corresponding bitfield in the header register with the appropriate value.

        :param value: Memory type to be set for the configuration
        :raises SPSDKValueError: When the specified memory type is not supported
        """
        if value not in self.supported_mem_types:
            raise SPSDKValueError(f"Memory type {value.tag} is not supported")
        self._header_reg.find_bitfield("memoryInterface").set_value(
            MEMORY_INTERFACE_TO_VALUE[value]
        )

    @property
    def supported_mem_types(self) -> list[MemoryType]:
        """Get list of supported memory types.

        Retrieves all memory types that are supported for the current MCU family
        from the XMCD database configuration.

        :return: List of supported memory types for the family.
        """
        mem_types = get_db(self.family).get_dict(DatabaseManager.XMCD, "mem_types", default={})
        return [MemoryType.from_label(mem_type) for mem_type in mem_types.keys()]

    @property
    def config_type(self) -> ConfigurationBlockType:
        """Get configuration block type from header register.

        Retrieves the configuration block type value from the header register's
        configurationBlockType bitfield and converts it to the appropriate enum type.

        :return: Configuration block type enum value.
        :raises SPSDKError: If the configuration block type value is invalid.
        """
        block_type = self._header_reg.find_bitfield("configurationBlockType").get_value()
        return ConfigurationBlockType.from_tag(block_type)

    @property
    def xmcd_size(self) -> int:
        """Get the size of configuration block including XMCD header itself.

        :return: Size of the configuration block in bytes.
        """
        return self._header_reg.find_bitfield("configurationBlockSize").get_value()

    @property
    def config_block_size(self) -> int:
        """Get the size of XMCD configuration data blob.

        Calculates the size of the configuration data portion by subtracting the base XMCD
        structure size from the total XMCD size. Returns 0 if the calculated size would be
        negative.

        :return: Size of the configuration data blob in bytes, or 0 if no config data exists.
        """
        config_blob_size = self.xmcd_size - self.size
        return config_blob_size if config_blob_size > 0 else 0

    def __repr__(self) -> str:
        """Return string representation of XMCD Header.

        :return: String representation of the XMCD Header object.
        """
        return "XMCD Header"

    def __str__(self) -> str:
        """String representation of the XMCD Header.

        Creates a formatted string containing the interface type, configuration type,
        and configuration size information from the XMCD header.

        :return: Formatted string with XMCD header information including interface,
            config type, and size details.
        """
        msg = ""
        msg += f" Interface:   {self.mem_type.description}\n"
        msg += f" Config type: {self.config_type.description}\n"
        msg += f" Config size: {self.xmcd_size} Bytes (including header)\n"
        return msg

    def parse(self, data: bytes) -> None:
        """Parse XMCD Header from binary data.

        :param data: Binary data containing the XMCD header information to be parsed.
        :raises SPSDKError: If the data cannot be parsed or is invalid.
        """
        self.registers.parse(data)

    def verify(
        self,
        mem_type: Optional[MemoryType] = None,
        config_type: Optional[ConfigurationBlockType] = None,
        xmcd_size: Optional[int] = None,
    ) -> Verifier:
        """Verify XMCD header data against expected values and constraints.

        Performs comprehensive validation of XMCD header fields including tag verification,
        version checking, configuration block size validation, configuration block type
        verification, and memory interface validation against supported types.

        :param mem_type: Expected memory type to validate against, optional validation if None.
        :param config_type: Expected configuration block type to validate against, optional
                           validation if None.
        :param xmcd_size: Expected XMCD size to validate against, validates size > header
                         size if None.
        :return: Verifier object containing all validation results and status information.
        """
        ret = Verifier("XMCD Header")
        ret.add_record(
            "Tag",
            self._header_reg.find_bitfield("tag").get_value() == self.TAG,
            hex(self.TAG),
        )
        ret.add_record(
            "Version",
            self._header_reg.find_bitfield("version").get_value() == 0,
            "Version has fixed value 0",
        )
        if xmcd_size:
            ret.add_record(
                "Configuration block size",
                self.xmcd_size == xmcd_size,
                self.xmcd_size,
            )
        else:
            ret.add_record(
                "Configuration block size",
                self.xmcd_size > self.size,
                "Must be higher than header",
            )
        if config_type:
            ret.add_record(
                "Configuration block type",
                config_type.tag == self.config_type,
                self.config_type.label,
            )
        else:
            ret.add_record_range(
                "Configuration block type",
                self._header_reg.find_bitfield("configurationBlockType").get_value(),
                min_val=0,
                max_val=1,
            )

        if mem_type:
            ret.add_record("Memory interface", mem_type == self.mem_type, self.mem_type.label)
        ret.add_record_range(
            "Memory interface",
            MEMORY_INTERFACE_TO_VALUE[self.mem_type],
            min_val=0,
            max_val=1,
        )
        ret.add_record_contains(
            "Memory interface is supported",
            self._header_reg.find_bitfield("memoryInterface").get_value(),
            collection=[MEMORY_INTERFACE_TO_VALUE[item] for item in self.supported_mem_types],
        )
        return ret


class XMCD(SegmentBase):
    """XMCD (External Memory Configuration Data) segment.

    This class manages external memory configuration data for NXP MCUs, providing
    functionality to create, validate, and export XMCD segments. It handles different
    memory types and configuration block types (simplified or full) with automatic
    register management and CRC calculation.

    :cvar FEATURE: Database feature identifier for XMCD operations.
    """

    FEATURE = DatabaseManager.XMCD

    def __init__(
        self, family: FamilyRevision, mem_type: MemoryType, config_type: ConfigurationBlockType
    ) -> None:
        """Initialize XMCD (External Memory Configuration Data) instance.

        Creates an XMCD object for specific chip family, memory type, and configuration block type.
        Initializes internal registers based on the provided parameters.

        :param family: Chip family and revision information.
        :param mem_type: Type of external memory to configure.
        :param config_type: Configuration block type (simplified or full).
        :raises SPSDKKeyError: Unsupported combination of memory type and configuration type.
        """
        super().__init__(family)
        self.mem_type = mem_type
        self.config_type = config_type

        try:
            self._registers = Registers(
                family=family,
                feature=DatabaseManager.XMCD,
                base_key=["mem_types", mem_type.label, config_type.label],
                base_endianness=Endianness.LITTLE,
            )
        except KeyError as exc:
            raise SPSDKKeyError(
                f"Unsupported combination: {mem_type.label}:{config_type.label}"
            ) from exc

    @property
    def registers(self) -> Registers:
        """Get configuration block registers with conditional option handling.

        Creates a deep copy of the internal registers and conditionally removes the
        configOption1 register based on the optionSize bitfield value in configOption0.
        If optionSize is 0, configOption1 is removed from the register set.

        :return: Deep copy of registers with conditional configOption1 removal.
        """
        regs = deepcopy(self._registers)
        try:
            # The existence of configOption1 is determined by optionSize value
            if regs.find_reg("configOption0").find_bitfield("optionSize").get_value() == 0:
                regs.remove_register("configOption1")
        except (SPSDKRegsErrorRegisterNotFound, SPSDKRegsErrorBitfieldNotFound):
            pass
        return regs

    @property
    def size(self) -> int:
        """Get the size of XMCD data in bytes.

        :return: Size of the exported XMCD data in bytes.
        """
        return len(self.export())

    @property
    def crc(self) -> bytes:
        """Get CRC value of XMCD object.

        :return: CRC value as bytes.
        """
        return self.calculate_crc()

    @staticmethod
    def pre_parse_verify(data: bytes, family: FamilyRevision) -> Verifier:
        """Pre-parse verify of XMCD data.

        Performs initial verification of XMCD (External Memory Configuration Data) binary data
        by parsing the header and validating its structure against the specified device family.

        :param data: Binary data with XMCD to be verified.
        :param family: Device family revision for validation context.
        :return: Verifier object containing pre-parsed binary data verification results.
        """
        ret = Verifier("Pre-parsed XMCD")
        header = XMCDHeader(family)
        header.parse(data)
        ret.add_child(header.verify())
        return ret

    def verify(self) -> Verifier:
        """Verify XMCD data integrity and configuration.

        Creates a verification report by parsing the XMCD header and validating
        it against the current configuration parameters including config type,
        memory type, and data size.

        :return: Verification report containing validation results for XMCD data.
        """
        ret = Verifier("XMCD")
        header = XMCDHeader(self.family)
        header.parse(self._registers.find_reg("header").get_bytes_value())
        ret.add_child(
            header.verify(
                config_type=self.config_type,
                mem_type=self.mem_type,
                xmcd_size=len(self.registers.export()),
            )
        )

        return ret

    @classmethod
    def parse(
        cls, binary: bytes, offset: int = 0, family: FamilyRevision = FamilyRevision("Unknown")
    ) -> Self:
        """Parse binary block into XMCD object.

        This method creates an XMCD instance by parsing the provided binary data, starting from the
        specified offset. It first parses and verifies the XMCD header, then creates the object
        with the appropriate configuration.

        :param binary: Binary image containing XMCD data.
        :param offset: Offset of XMCD in binary image.
        :param family: Chip family revision information.
        :raises SPSDKError: If given binary block size is not equal to block size in header.
        :return: Parsed XMCD object instance.
        """
        binary = binary[offset:]
        header: XMCDHeader = XMCDHeader(family)
        header.parse(binary)
        header.verify().validate()
        xmcd = cls(family=family, mem_type=header.mem_type, config_type=header.config_type)
        xmcd._registers.parse(binary[: header.xmcd_size])
        return xmcd

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        This method validates the basic configuration structure, extracts family revision,
        memory type, and configuration block type from the config, then returns the
        appropriate validation schemas for those parameters.

        :param config: Valid configuration object containing family, memory type, and config type.
        :return: List of validation schema dictionaries for the specified configuration.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config["mem_type"])
        conf_block_type = ConfigurationBlockType.from_label(config["config_type"])
        return cls.get_validation_schemas(family, mem_type, conf_block_type)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load XMCD object from configuration.

        Creates and initializes an XMCD (External Memory Configuration Data) object
        from the provided configuration settings including family, memory type,
        configuration type, and register settings.

        :param config: Configuration object containing XMCD settings.
        :raises SPSDKValueError: Invalid configuration values or missing required fields.
        :return: Initialized XMCD object with loaded configuration.
        """
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config.get_str("mem_type"))
        config_type = ConfigurationBlockType.from_label(config.get_str("config_type"))

        xmcd_settings = config.get_config("xmcd_settings")

        xmcd = cls(family=family, mem_type=mem_type, config_type=config_type)
        xmcd._registers.load_from_config(xmcd_settings)

        return xmcd

    def calculate_crc(self) -> bytes:
        """Calculate XMCD CRC value.

        Computes the CRC32 MPEG checksum for the XMCD data using the exported binary
        representation of the XMCD structure.

        :return: 4-byte CRC value in big-endian format.
        """
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        crc_bytes = crc_obj.calculate(self.export()).to_bytes(
            length=4, byteorder=Endianness.BIG.value
        )
        return crc_bytes

    def create_crc_hash_fuses_script(self) -> str:
        """Create fuses script of CRC hash.

        Generates a fuse script for programming CRC hash values into the device fuses. The method
        handles cases where CRC hash fuses are not available for the specified family.

        :return: Fuse script content as string, or error message if CRC hash fuses are not available.
        """
        try:
            fuse_script = FuseScript(self.family, DatabaseManager.XMCD)
        except SPSDKError as exc:
            return f"The CRC hash fuses are not available: {exc.description}"
        return fuse_script.generate_script(self)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the XMCD.

        The method generates a configuration dictionary containing family information, memory type,
        configuration type, and XMCD register settings.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary with XMCD settings.
        """
        config = Config()
        config["family"] = self.family.name
        config["revision"] = self.family.revision
        config["mem_type"] = self.mem_type.label
        config["config_type"] = self.config_type.label
        config["xmcd_settings"] = dict(self.registers.get_config())

        return config

    def _get_validation_schemas(self) -> list[dict[str, Any]]:
        """Get validation schema for the object.

        The method retrieves validation schemas based on the object's family, memory type,
        and configuration type properties.

        :return: List of validation schema dictionaries.
        """
        return self.get_validation_schemas(self.family, self.mem_type, self.config_type)

    @classmethod
    def get_validation_schemas(
        cls,
        family: FamilyRevision,
        mem_type: MemoryType = MemoryType.FLEXSPI_NOR,
        config_type: ConfigurationBlockType = ConfigurationBlockType.SIMPLIFIED,
    ) -> list[dict[str, Any]]:
        """Create the validation schema for XMCD configuration.

        This method generates validation schemas for External Memory Configuration Data
        based on the specified family, memory type, and configuration type. It updates
        the schema with supported options and creates register validation schemas.

        :param family: Family description specifying the target MCU family.
        :param mem_type: Used memory type for the configuration.
        :param config_type: Configuration type, either simplified or full.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas for XMCD configuration.
        """
        sch_cfg = get_schema_file(DatabaseManager.XMCD)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], XMCD.get_supported_families(), family
        )
        sch_family["main_title"] = f"External Memory Configuration Data for {family}."
        sch_family["note"] = "Note for settings:\n" + Registers.TEMPLATE_NOTE
        sch_cfg["memory_type"]["properties"]["mem_type"]["enum"] = [
            mem_type.label for mem_type in XMCD.get_supported_memory_types(family)
        ]
        sch_cfg["memory_type"]["properties"]["mem_type"]["template_value"] = mem_type.label
        sch_cfg["config_type"]["properties"]["config_type"]["enum"] = [
            config.label for config in cls.get_supported_configuration_types(family, mem_type)
        ]
        sch_cfg["config_type"]["properties"]["config_type"]["template_value"] = config_type.label

        sch_cfg["xmcd"]["properties"]["xmcd_settings"] = Registers(
            family=family,
            feature=cls.FEATURE,
            base_key=["mem_types", mem_type.label, config_type.label],
        ).get_validation_schema()

        return [sch_family, sch_cfg["memory_type"], sch_cfg["config_type"], sch_cfg["xmcd"]]

    @classmethod
    def get_validation_schemas_basic(cls) -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        The method generates validation schemas for XMCD configuration by combining
        family validation schema with memory type and config type schemas. It updates
        the family schema to include only the families supported by XMCD.

        :return: List of validation schemas containing family, memory type, and config
            type schemas for XMCD supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.XMCD)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], XMCD.get_supported_families())
        return [sch_family, sch_cfg["memory_type"], sch_cfg["config_type"]]

    @classmethod
    def get_config_template(
        cls,
        family: FamilyRevision,
        mem_type: MemoryType = MemoryType.FLEXSPI_RAM,
        config_type: ConfigurationBlockType = ConfigurationBlockType.FULL,
    ) -> str:
        """Generate configuration template for selected family and memory type.

        :param family: Family description specifying the target MCU family.
        :param mem_type: Used memory type, defaults to FLEXSPI_RAM.
        :param config_type: Configuration type - either simplified or full block type.
        :return: Template of XMCD Block configuration as string.
        """
        schemas = XMCD.get_validation_schemas(family, mem_type, config_type)
        return cls._get_config_template(family, schemas)

    @classmethod
    def get_supported_configuration_types(
        cls, family: FamilyRevision, mem_type: MemoryType
    ) -> list[ConfigurationBlockType]:
        """Get supported configuration types for given family and memory type.

        The method retrieves available configuration block types from the database
        for the specified family and memory type combination.

        :param family: Target MCU family and revision.
        :param mem_type: Memory type to get configuration types for.
        :return: List of supported configuration block types.
        """
        mem_types = get_db(family).get_dict(DatabaseManager.XMCD, "mem_types", default={})
        return [
            ConfigurationBlockType.from_label(block_type)
            for block_type in list(mem_types[mem_type.label].keys())
        ]

    def __repr__(self) -> str:
        """Return string representation of XMCD segment.

        Provides a formatted string containing the family, memory type, and configuration
        type information for the XMCD segment.

        :return: Formatted string representation of the XMCD segment.
        """
        return (
            f"XMCD Segment:\n"
            f" Family: {self.family}\n"
            f"Memory type: {self.mem_type.description}\n"
            f"Config type: {self.config_type.description}"
        )

    def __str__(self) -> str:
        """Return string representation of XMCD segment.

        Provides a formatted string containing the family, memory type, and configuration
        type information of the XMCD segment.

        :return: Formatted string with XMCD segment details.
        """
        return (
            "XMCD Segment:\n"
            f" Family:           {self.family}\n"
            f" Memory type:      {self.mem_type}\n"
            f" Config type:      {self.config_type}\n"
        )
