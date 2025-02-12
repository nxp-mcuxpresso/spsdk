#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains XMCD (External Memory Configuration Data) related code."""


import datetime
import logging
from copy import deepcopy
from typing import Any

from typing_extensions import Self

from spsdk import version as spsdk_version
from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.fuses.fuses import FuseScript
from spsdk.image.mem_type import MemoryType
from spsdk.image.segments_base import SegmentBase
from spsdk.utils.database import DatabaseManager, get_db, get_schema_file
from spsdk.utils.exceptions import SPSDKRegsErrorBitfieldNotFound, SPSDKRegsErrorRegisterNotFound
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import (
    CommentedConfig,
    check_config,
    update_validation_schema_family,
)
from spsdk.utils.spsdk_enum import SpsdkEnum
from spsdk.utils.verifier import Verifier

logger = logging.getLogger(__name__)


class ConfigurationBlockType(SpsdkEnum):
    """Support configuration blocks Enum."""

    SIMPLIFIED = (0, "simplified", "Simplified configuration")
    FULL = (1, "full", "Full configuration")


MEMORY_INTERFACE_TO_VALUE: dict[MemoryType, int] = {
    MemoryType.FLEXSPI_RAM: 0,
    MemoryType.XSPI_RAM: 0,
    MemoryType.SEMC_SDRAM: 1,
}


class XMCDHeader:
    """External Memory Configuration Data Header."""

    TAG = 0x0C

    def __init__(self, family: str, revision: str = "latest") -> None:
        """Initialize the XMCD Header."""
        self.family = family
        self.revision = revision
        self.registers: Registers = self._init_registers(family, revision)
        self._header_reg = self.registers.find_reg("header")

    @property
    def size(self) -> int:
        """Header size."""
        return len(self.export())

    @staticmethod
    def _init_registers(family: str, revision: str = "latest") -> Registers:
        """Load header registers of segment.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        """
        return Registers(
            family=family,
            feature=DatabaseManager.XMCD,
            base_key="header",
            revision=revision,
            base_endianness=Endianness.LITTLE,
        )

    def export(self) -> bytes:
        """Export segment's header as bytes (serialization).

        :return: Binary representation of segment.
        """
        return self.registers.image_info().export()

    @property
    def mem_type(self) -> MemoryType:
        """Memory type property."""
        mem_type = self._header_reg.find_bitfield("memoryInterface").get_value()
        for sup_mem_type in self.supported_mem_types:
            if MEMORY_INTERFACE_TO_VALUE[sup_mem_type] == mem_type:
                return sup_mem_type
        raise SPSDKValueError(f"Memory type with index {mem_type} is not supported")

    @mem_type.setter
    def mem_type(self, value: MemoryType) -> None:
        """Memory type property setter."""
        if value not in self.supported_mem_types:
            raise SPSDKValueError(f"Memory type {value.tag} is not supported")
        self._header_reg.find_bitfield("memoryInterface").set_value(
            MEMORY_INTERFACE_TO_VALUE[value]
        )

    @property
    def supported_mem_types(self) -> list[MemoryType]:
        """Get list if supported memory types."""
        mem_types = get_db(self.family, self.revision).get_dict(
            DatabaseManager.XMCD, "mem_types", default={}
        )
        return [MemoryType.from_label(mem_type) for mem_type in mem_types.keys()]

    @property
    def config_type(self) -> ConfigurationBlockType:
        """Config type property."""
        block_type = self._header_reg.find_bitfield("configurationBlockType").get_value()
        return ConfigurationBlockType.from_tag(block_type)

    @config_type.setter
    def config_type(self, value: ConfigurationBlockType) -> None:
        """Config type property setter."""
        self._header_reg.find_bitfield("configurationBlockType").set_value(value.tag)

    @property
    def xmcd_size(self) -> int:
        """The size of configuration block including XMCD header itself."""
        return self._header_reg.find_bitfield("configurationBlockSize").get_value()

    @xmcd_size.setter
    def xmcd_size(self, value: int) -> None:
        """XMCD size setter."""
        return self._header_reg.find_bitfield("configurationBlockSize").set_value(value)

    @property
    def config_block_size(self) -> int:
        """Size of XMCD config data blob."""
        config_blob_size = self.xmcd_size - self.size
        return config_blob_size if config_blob_size > 0 else 0

    def __repr__(self) -> str:
        return "XMCD Header"

    def __str__(self) -> str:
        """String representation of the XMCD Header."""
        msg = ""
        msg += f" Interface:   {self.mem_type.description}\n"
        msg += f" Config type: {self.config_type.description}\n"
        msg += f" Config size: {self.xmcd_size} Bytes (including header)\n"
        return msg

    def parse(self, data: bytes) -> None:
        """Parse XMCD Header from binary data."""
        self.registers.parse(data)

    def load_from_config(self, config: dict) -> None:
        """Load from XMCD configuration.

        :param config: XMCD configuration.
        """
        self.registers.load_yml_config(config)

    def verify(self) -> Verifier:
        """Verify XMCD header data."""
        ret = Verifier("XMCD Header")
        ret.add_record(
            "Tag",
            self._header_reg.find_bitfield("tag").get_value() == self.TAG,
            f"Does not match the tag {self.TAG}",
        )
        ret.add_record(
            "Version",
            self._header_reg.find_bitfield("version").get_value() == 0,
            "Version has fixed value 0",
        )
        ret.add_record(
            "Configuration block size",
            self._header_reg.find_bitfield("configurationBlockSize").get_value() > self.size,
            "Must be higher than header",
        )
        ret.add_record_range(
            "Configuration block type",
            self._header_reg.find_bitfield("configurationBlockType").get_value(),
            min_val=0,
            max_val=1,
        )
        ret.add_record_range(
            "Memory interface",
            self._header_reg.find_bitfield("memoryInterface").get_value(),
            min_val=0,
            max_val=1,
        )
        ret.add_record_contains(
            "Memory interface is supported",
            self._header_reg.find_bitfield("memoryInterface").get_value(),
            collection=[MEMORY_INTERFACE_TO_VALUE[item] for item in self.supported_mem_types],
        )
        return ret


class XMCDConfigBlock:
    """External Memory Configuration Data Configuration Block."""

    def __init__(
        self,
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str = "latest",
    ) -> None:
        """Initialize the XMCD Config Block."""
        self._registers: Registers = self._init_registers(family, mem_type, config_type, revision)

    @property
    def size(self) -> int:
        """Config block size."""
        return len(self.export())

    @staticmethod
    def _init_registers(
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str = "latest",
    ) -> Registers:
        """Load block registers of segment.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKKeyError: Unknown mem_type or config type
        """
        try:
            return Registers(
                family=family,
                feature=DatabaseManager.XMCD,
                base_key=["mem_types", mem_type.label, config_type.label],
                revision=revision,
                base_endianness=Endianness.LITTLE,
            )
        except KeyError as exc:
            raise SPSDKKeyError(
                f"Unsupported combination: {mem_type.label}:{config_type.label}"
            ) from exc

    def export(self) -> bytes:
        """Export segment's header as bytes (serialization).

        :return: Binary representation of segment.
        """
        return self.registers.image_info().export()

    @property
    def registers(self) -> Registers:
        """Configuration block registers."""
        regs = deepcopy(self._registers)
        try:
            # The existence of configOption1 is determined by optionSize value
            if regs.find_reg("configOption0").find_bitfield("optionSize").get_value() == 0:
                regs.remove_register("configOption1")
        except (SPSDKRegsErrorRegisterNotFound, SPSDKRegsErrorBitfieldNotFound):
            pass
        return regs

    def parse(self, data: bytes) -> None:
        """Parse XMCD Header from binary data."""
        self._registers.parse(data)

    def load_from_config(self, config: dict) -> None:
        """Load from XMCD configuration.

        :param config: XMCD configuration.
        """
        self._registers.load_yml_config(config)

    def verify(self) -> Verifier:
        """Verify XMCD config block data."""
        ret = Verifier("XMCD Config Block")
        return ret


class XMCD(SegmentBase):
    """XMCD (External Memory Configuration Data)."""

    FEATURE = DatabaseManager.XMCD

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
        """
        super().__init__(family, revision)
        self.header = XMCDHeader(family, revision)
        self.config_block = XMCDConfigBlock(family, mem_type, config_type, revision)
        self.header.mem_type = mem_type
        self.header.config_type = config_type
        self.header.xmcd_size = self.header.size + self.config_block.size

    @property
    def registers(self) -> Registers:
        """Merged XMCD registers containing header and configuration block."""
        header_regs = deepcopy(self.header.registers)
        config_block_regs = deepcopy(self.config_block.registers)

        regs = header_regs
        for register in config_block_regs.get_registers():
            register.offset += self.header.size
            regs.add_register(register)
        return regs

    @property
    def size(self) -> int:
        """XMCD size."""
        return len(self.export())

    @property
    def mem_type(self) -> MemoryType:
        """Memory type."""
        return self.header.mem_type

    @property
    def crc(self) -> bytes:
        """CRC value if XMCD object.

        :return: SHA256 hash of SRK table.
        """
        return self.calculate_crc()

    @property
    def config_type(self) -> ConfigurationBlockType:
        """Configuration type. It can be either simplified or full."""
        return self.header.config_type

    def verify(self) -> Verifier:
        """Verify XMCD data."""
        ret = Verifier("XMCD")
        ret.add_child(self.header.verify())
        ret.add_child(self.config_block.verify())
        ret.add_record(
            "Size",
            self.header.xmcd_size == self.size,
            "The configurationBlockSize does not match the actual size",
        )
        return ret

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
        header: XMCDHeader = XMCDHeader(family, revision)
        header.parse(binary)
        xmcd = cls(
            family=family,
            mem_type=header.mem_type,
            config_type=header.config_type,
            revision=revision,
        )
        xmcd.header.parse(binary[: header.size])
        xmcd.config_block.parse(binary[header.size :])
        return xmcd

    @classmethod
    def load_from_config(cls, config: dict) -> Self:
        """Load from XMCD configuration.

        :param config: XMCD configuration.
        :return: XMCD object.
        """
        check_config(config, XMCD.get_validation_schemas_family())
        family = config["family"]
        revision = config.get("revision", "latest")
        mem_type = MemoryType.from_label(config["mem_type"])
        config_type = ConfigurationBlockType.from_label(config["config_type"])
        check_config(config, XMCD.get_validation_schemas(family, mem_type, config_type, revision))

        xmcd_settings: dict[str, dict] = config["xmcd_settings"]

        xmcd = cls(family=family, mem_type=mem_type, config_type=config_type, revision=revision)
        xmcd.header.load_from_config({"header": xmcd_settings.pop("header")})
        xmcd.config_block.load_from_config(xmcd_settings)
        xmcd_size = len(xmcd.registers.image_info())
        if xmcd.header.xmcd_size != xmcd_size:
            logger.warning(
                f"The configurationBlockSize '{xmcd.header.xmcd_size}' is not valid."
                f"The calculated value '{xmcd_size}' will be used instead."
            )
            xmcd.header.xmcd_size = len(xmcd.registers.image_info())
        return xmcd

    def calculate_crc(self) -> bytes:
        """Calculate XMCD CRC value."""
        crc_obj = from_crc_algorithm(CrcAlg.CRC32_MPEG)
        crc_bytes = crc_obj.calculate(self.export()).to_bytes(
            length=4, byteorder=Endianness.BIG.value
        )
        return crc_bytes

    def create_crc_hash_fuses_script(self) -> str:
        """Create fuses script of CRC hash."""
        try:
            fuse_script = FuseScript(self.family, self.revision, DatabaseManager.XMCD)
        except SPSDKError as exc:
            return f"The CRC hash fuses are not available: {exc.description}"
        return fuse_script.generate_script(self)

    def create_config(self) -> str:
        """Create current configuration YAML.

        :raises SPSDKError: Registers are not loaded in the object.
        :return: Configuration of XMCD Block.
        """
        config: dict[str, Any] = {}
        config["family"] = self.family
        config["revision"] = self.revision
        config["mem_type"] = self.mem_type.label
        config["config_type"] = self.config_type.label
        if len(self.registers.get_registers()) == 0:
            raise SPSDKError(
                "Registers are not loaded. Load the configuration or parse binary first."
            )
        config["xmcd_settings"] = self.registers.get_config()
        schemas = self.get_validation_schemas(
            family=self.family,
            mem_type=self.mem_type,
            config_type=self.config_type,
            revision=self.revision,
        )
        return CommentedConfig(
            main_title=(
                f"XMCD configuration for {self.family}.\n"
                f"Created: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}.\n"
                f"NXP SPSDK version: {spsdk_version}"
            ),
            schemas=schemas,
        ).get_config(config)

    @classmethod
    def get_validation_schemas(
        cls,
        family: str,
        mem_type: MemoryType,
        config_type: ConfigurationBlockType,
        revision: str = "latest",
    ) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.XMCD)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], XMCD.get_supported_families(), family, revision
        )
        sch_cfg["memory_type"]["properties"]["mem_type"]["enum"] = [
            mem_type.label for mem_type in XMCD.get_supported_memory_types(family, revision)
        ]
        sch_cfg["memory_type"]["properties"]["mem_type"]["template_value"] = mem_type.label
        sch_cfg["config_type"]["properties"]["config_type"]["enum"] = [
            config.label
            for config in cls.get_supported_configuration_types(family, mem_type, revision)
        ]
        sch_cfg["config_type"]["properties"]["config_type"]["template_value"] = config_type.label

        registers = XMCD(family, mem_type, config_type, revision).registers
        sch_cfg["xmcd"]["properties"]["xmcd_settings"] = registers.get_validation_schema()

        return [sch_family, sch_cfg["memory_type"], sch_cfg["config_type"], sch_cfg["xmcd"]]

    @staticmethod
    def get_validation_schemas_family() -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for XMCD supported families.
        """
        sch_cfg = get_schema_file(DatabaseManager.XMCD)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(sch_family["properties"], XMCD.get_supported_families())
        return [sch_family, sch_cfg["memory_type"], sch_cfg["config_type"]]

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
        schemas = XMCD.get_validation_schemas(family, mem_type, config_type, revision)

        ret = CommentedConfig(
            main_title=f"External Memory Configuration Data template for {family}.",
            schemas=schemas,
            note="Note for settings:\n" + Registers.TEMPLATE_NOTE,
        ).get_template()

        return ret

    @classmethod
    def get_supported_configuration_types(
        cls, family: str, mem_type: MemoryType, revision: str = "latest"
    ) -> list[ConfigurationBlockType]:
        """Return list of supported memory interfaces.

        :return: List of supported family interfaces.
        """
        mem_types = get_db(family, revision).get_dict(DatabaseManager.XMCD, "mem_types", default={})
        return [
            ConfigurationBlockType.from_label(block_type)
            for block_type in list(mem_types[mem_type.label].keys())
        ]

    def __repr__(self) -> str:
        return (
            f"XMCD Segment:\n"
            f" Family: {self.family}\n"
            f" Revision: {self.revision}\n"
            f"Memory type: {self.mem_type.description}\n"
            f"Config type: {self.config_type.description}"
        )

    def __str__(self) -> str:
        return (
            "XMCD Segment:\n"
            f" Family:           {self.family}\n"
            f" Revision:         {self.revision}\n"
            f" Memory type:      {self.mem_type}\n"
            f" Config type:      {self.config_type}\n"
        )
