#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains XMCD (External Memory Configuration Data) related code."""


import datetime
import logging
import os
from copy import deepcopy
from typing import Any, Dict, List, Optional

from crcmod.predefined import mkPredefinedCrcFun
from ruamel.yaml.comments import CommentedMap as CM
from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.image.segments import XMCDHeader
from spsdk.image.segments_base import SegmentBase
from spsdk.image.xmcd import XMCD_DATA_FOLDER, XMCD_DATABASE_FILE, XMCD_SCH_FILE
from spsdk.utils.database import Database
from spsdk.utils.easy_enum import Enum
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas, check_config

logger = logging.getLogger(__name__)


class MemoryType(Enum):
    """Support memory types Enum."""

    FLEXSPI_RAM = (0, "flexspi_ram", "FlexSPI RAM")
    SEMC_SDRAM = (1, "semc_sdram", "SEMC SDRAM")


class ConfigurationBlockType(Enum):
    """Support configuration blocks Enum."""

    SIMPLIFIED = (0, "simplified", "Simplified configuration")
    FULL = (1, "full", "Full configuration")


class XMCD(SegmentBase):
    """XMCD (External Memory Configuration Data)."""

    def __init__(
        self,
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str = "latest",
    ) -> None:
        """XMCD Constructor.

        :param family: Chip family.
        :param config_type: Configuration block type: simplified | full.
        :param revision: Optional Chip family revision.
        :raises SPSDKValueError: Unsupported family.
        """
        super().__init__(family, revision)
        self.mem_type: MemoryType = mem_type
        self.config_type: ConfigurationBlockType = config_type
        self._registers: Registers = Registers(family, base_endianness="little")

    @property
    def mem_type(self) -> MemoryType:
        """Memory type."""
        return self._mem_type

    @mem_type.setter
    def mem_type(self, value: MemoryType) -> None:
        """Memory type setter.

        :param value: Value to be set.
        :raises SPSDKValueError: If givem memory type is not supported
        """
        mem_types = XMCD.get_supported_memory_types(self.family, self.revision)
        if MemoryType.name(value) not in mem_types:
            raise SPSDKValueError(
                f"Unsupported memory type:{MemoryType.name(value)} not in {mem_types}"
            )
        self._mem_type = value

    @property
    def config_type(self) -> ConfigurationBlockType:
        """Configuration type. It can be either simplified or full."""
        return self._config_type

    @config_type.setter
    def config_type(self, value: ConfigurationBlockType) -> None:
        """Configuration type setter.

        :param value: Value to be set.
        :raises SPSDKValueError: If givem configuration type is not supported
        """
        supported_config_types = XMCD.get_supported_configuration_types(
            self.family, self.mem_type, self.revision
        )
        if ConfigurationBlockType.name(value) not in supported_config_types:
            raise SPSDKValueError(
                f"Unsupported config type:{ConfigurationBlockType.name(value)} not in {supported_config_types}"
            )
        self._config_type = value

    @property
    def registers(self) -> Registers:
        """Registers of segment."""
        return self._registers

    @registers.setter
    def registers(self, value: Registers) -> None:
        """Registers of segment."""
        self._registers = value

    @staticmethod
    def get_database() -> Database:
        """Get the devices database."""
        return Database(XMCD_DATABASE_FILE)

    @classmethod
    def parse(
        cls, binary: bytes, offset: int = 0, family: str = "Unknown", revision: str = "latest"
    ) -> Self:
        """Parse binary block into XMCD object.

        :param binary: binary image.
        :param offset: Offset of XMCD in binary image.
        :param family: Chip family.
        :param revision: Optional Chip family revision.
        :raises SPSDKError: If given binary block size is not equal to block size in header
        """
        binary = binary[offset:]
        header = XMCDHeader.parse(binary[: XMCDHeader.SIZE])
        mem_type = MemoryType.from_int(header.interface)
        config_type = ConfigurationBlockType.from_int(header.block_type)
        filter_reg = None
        # Flexspi simplified confgiruation may contain one or two configOption words
        if (
            mem_type == MemoryType.FLEXSPI_RAM
            and config_type == ConfigurationBlockType.SIMPLIFIED
            and len(binary) == 8
        ):
            filter_reg = ["configOption1"]
        registers = cls.load_registers(
            family, mem_type, config_type, revision, filter_reg=filter_reg
        )
        registers.parse(binary)
        crc = cls.calculate_crc(binary)
        logger.info(f"CRC value: {crc!r}")

        xmcd = cls(family=family, mem_type=mem_type, config_type=config_type, revision=revision)
        xmcd.registers = registers
        xmcd._validate()
        return xmcd

    @staticmethod
    def load_from_config(config: Dict) -> "XMCD":
        """Load configuration file of XMCD.

        :param config: XMCD configuration file.
        :raises SPSDKKeyError: If XMCD settings do not contain required key
        :return: XMCD object.
        """
        check_config(config, XMCD.get_validation_schemas_family())
        family = config["family"]
        revision = config.get("revision", "latest")
        mem_type = MemoryType.from_int(MemoryType[config["mem_type"]])
        config_type = ConfigurationBlockType.from_int(ConfigurationBlockType[config["config_type"]])
        check_config(config, XMCD.get_validation_schemas(family, mem_type, config_type, revision))

        xmcd_settings: Dict[str, Dict] = config["xmcd_settings"]

        xmcd = XMCD(family=family, mem_type=mem_type, config_type=config_type, revision=revision)

        filter_reg = None
        if (
            xmcd.mem_type == MemoryType.FLEXSPI_RAM
            and xmcd.config_type == ConfigurationBlockType.SIMPLIFIED
        ):
            # Simplified flexspi_ram can contain one or two option words
            config_options = {"configOption0", "configOption1"}
            filter_reg = list(config_options - set(xmcd_settings.keys()))
        xmcd.registers = xmcd.load_registers(
            xmcd.family, xmcd.mem_type, xmcd.config_type, xmcd.revision, filter_reg=filter_reg
        )
        xmcd.registers.load_yml_config(xmcd_settings)
        xmcd._validate()
        return xmcd

    def _validate(self) -> None:
        """Validate the register values."""
        block_size = (
            self.registers.find_reg("header").find_bitfield("configurationBlockSize").get_value()
        )
        if block_size != len(self.export()):
            raise SPSDKError(
                "The configurationBlockSize bit field is not matching the size of XMCD"
            )

        if (
            self.mem_type == MemoryType.FLEXSPI_RAM
            and self.config_type == ConfigurationBlockType.SIMPLIFIED
        ):
            config_option_regs = [
                reg for reg in self.registers.get_reg_names() if reg.startswith("configOption")
            ]
            option_size = (
                self.registers.find_reg("configOption0").find_bitfield("optionSize").get_value()
            )
            if option_size != len(config_option_regs) - 1:
                raise SPSDKError(
                    "Option size in configOption0 does not match the number of registers."
                )

    @classmethod
    def calculate_crc(cls, data: bytes) -> bytes:
        """Calculate XMCD CRC value.

        :param data: Data to be used for calculation.
        """
        crc: int = mkPredefinedCrcFun("crc-32-mpeg")(data)
        crc_bytes = crc.to_bytes(4, "little")
        if len(crc_bytes) < 5:
            crc_bytes = crc_bytes.ljust(5, b"\0")
        return crc_bytes

    def create_config(self) -> str:
        """Create current configuration YAML.

        :raises SPSDKError: Registers are not loaded in the object.
        :return: Configuration of XMCD Block.
        """
        config = CM()
        config["family"] = self.family
        config["revision"] = self.revision
        config["mem_type"] = MemoryType.name(self.mem_type)
        config["config_type"] = ConfigurationBlockType.name(self.config_type)
        if len(self.registers.get_registers()) == 0:
            raise SPSDKError(
                "Registers are not loaded. Load the configuration or parse binary first."
            )
        config["xmcd_settings"] = self.registers.create_yml_config()
        config.yaml_set_start_comment(
            f"XMCD configuration for {self.family}.\n"
            f"Created: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
            f"NXP SPSDK version: {spsdk_version}"
        )
        return CommentedConfig.convert_cm_to_yaml(config)

    @classmethod
    def get_validation_schemas(
        cls,
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str = "latest",
    ) -> List[Dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(XMCD_SCH_FILE))
        sch_cfg["xmcd_family_rev"]["properties"]["family"]["enum"] = XMCD.get_supported_families()
        revisions = ["latest"]
        revisions.extend(XMCD.get_database().devices.get_by_name(family).revisions.revision_names)
        sch_cfg["xmcd_family_rev"]["properties"]["revision"]["enum"] = revisions
        sch_cfg["xmcd_family_rev"]["properties"]["mem_type"][
            "enum"
        ] = XMCD.get_supported_memory_types(family, revision)
        sch_cfg["xmcd_family_rev"]["properties"]["config_type"][
            "enum"
        ] = XMCD.get_supported_configuration_types(family, mem_type, revision)

        registers = XMCD.load_registers(family, mem_type, config_type, revision)
        sch_cfg["xmcd"]["properties"]["xmcd_settings"] = registers.get_validation_schema()

        return [sch_cfg["xmcd_family_rev"], sch_cfg["xmcd"]]

    @staticmethod
    def get_validation_schemas_family() -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for XMCD supported families.
        """
        sch_cfg = deepcopy(ValidationSchemas.get_schema_file(XMCD_SCH_FILE))
        sch_cfg["xmcd_family_rev"]["properties"]["family"]["enum"] = XMCD.get_supported_families()
        return [sch_cfg["xmcd_family_rev"]]

    @staticmethod
    def generate_config_template(
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str = "latest",
    ) -> str:
        """Generate configuration for selected family.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        :return: Template of XMCD Block.
        """
        try:
            schemas = XMCD.get_validation_schemas(family, mem_type, config_type, revision)
        except SPSDKError:
            return ""
        override = {}
        override["family"] = family
        override["revision"] = revision
        override["mem_type"] = MemoryType.name(mem_type)
        override["config_type"] = ConfigurationBlockType.name(config_type)

        ret = CommentedConfig(
            f"External Memory Configuration Data template for {family}.",
            schemas,
            override,
        ).export_to_yaml()

        return ret

    @classmethod
    def get_supported_configuration_types(
        cls, family: str, mem_type: MemoryType, revision: str = "latest"
    ) -> List[str]:
        """Return list of supported memory interfaces.

        :return: List of supported family interfaces.
        """
        mem_types = cls.get_memory_types(family, revision)
        return list(mem_types[MemoryType.name(mem_type)].keys())

    @staticmethod
    def _load_header_registers(
        family: str, mem_type: MemoryType, config_type: ConfigurationBlockType, revision: str
    ) -> Registers:
        """Load header registers of segment.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        """
        header_file_name = XMCD.get_database().get_device_value("header", family, revision)
        header_file_path = os.path.join(XMCD_DATA_FOLDER, header_file_name)
        regs = Registers(family, base_endianness="little")
        regs.load_registers_from_xml(header_file_path)
        header_reg = regs.find_reg("header")
        block_type_bf = header_reg.find_bitfield("configurationBlockType")
        block_type_bf.set_value(config_type)
        memory_if_bf = header_reg.find_bitfield("memoryInterface")
        memory_if_bf.set_value(mem_type)
        return regs

    @staticmethod
    def _load_block_registers(
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str,
        filter_reg: Optional[List[str]] = None,
    ) -> Registers:
        """Load block registers of segment.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        :param filter_reg: List of register names that should be filtered out.
        :raises SPSDKKeyError: Unknown mem_type or config type
        """
        mem_type_name = MemoryType.name(mem_type)
        config_type_name = ConfigurationBlockType.name(config_type)
        try:
            block_config = XMCD.get_memory_types(family, revision)[mem_type_name][config_type_name]
        except KeyError as exc:
            raise SPSDKKeyError(
                f"Unsupported combination: {mem_type_name}:{config_type_name}"
            ) from exc
        block_file_path = os.path.join(XMCD_DATA_FOLDER, block_config)
        regs = Registers(family, base_endianness="little")
        regs.load_registers_from_xml(block_file_path, filter_reg=filter_reg)
        return regs

    @staticmethod
    def load_registers(
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str,
        filter_reg: Optional[List[str]] = None,
    ) -> Registers:
        """Load all registers of segment.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        :param filter_reg: List of register names that should be filtered out.

        :raises SPSDKValueError: If option_size has invalid value(only 0 or 1 are allowed)
        """
        regs = XMCD._load_header_registers(family, mem_type, config_type, revision)
        block_regs = XMCD._load_block_registers(
            family, mem_type, config_type, revision, filter_reg=filter_reg
        )
        for block_reg in block_regs.get_registers():
            block_reg.offset += XMCDHeader.SIZE
            regs.add_register(block_reg)
        header_reg = regs.find_reg("header")
        config_block_size = header_reg.find_bitfield("configurationBlockSize")
        config_block_size.set_value(len(regs.image_info()))
        return regs

    def __repr__(self) -> str:
        return f"XMCD Segment, memory type: {self.mem_type}"

    def __str__(self) -> str:
        return (
            "XMCD Segment:\n"
            f" Family:           {self.family}\n"
            f" Revision:         {self.revision}\n"
            f" Memory type:      {self.mem_type}\n"
            f" Config type:      {self.config_type}\n"
        )
