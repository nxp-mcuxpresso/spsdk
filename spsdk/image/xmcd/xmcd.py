#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This module contains XMCD (External Memory Configuration Data) related code."""

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

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize the XMCD Header."""
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
        """Header size."""
        return len(self.registers)

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
        mem_types = get_db(self.family).get_dict(DatabaseManager.XMCD, "mem_types", default={})
        return [MemoryType.from_label(mem_type) for mem_type in mem_types.keys()]

    @property
    def config_type(self) -> ConfigurationBlockType:
        """Config type property."""
        block_type = self._header_reg.find_bitfield("configurationBlockType").get_value()
        return ConfigurationBlockType.from_tag(block_type)

    @property
    def xmcd_size(self) -> int:
        """The size of configuration block including XMCD header itself."""
        return self._header_reg.find_bitfield("configurationBlockSize").get_value()

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

    def verify(
        self,
        mem_type: Optional[MemoryType] = None,
        config_type: Optional[ConfigurationBlockType] = None,
        xmcd_size: Optional[int] = None,
    ) -> Verifier:
        """Verify XMCD header data."""
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
    """XMCD (External Memory Configuration Data)."""

    FEATURE = DatabaseManager.XMCD

    def __init__(
        self, family: FamilyRevision, mem_type: MemoryType, config_type: ConfigurationBlockType
    ) -> None:
        """XMCD Constructor.

        :param family: Chip family.
        :param config_type: Configuration block type: simplified | full.
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
        """Configuration block registers."""
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
        """XMCD size."""
        return len(self.export())

    @property
    def crc(self) -> bytes:
        """CRC value if XMCD object.

        :return: SHA256 hash of SRK table.
        """
        return self.calculate_crc()

    @staticmethod
    def pre_parse_verify(data: bytes, family: FamilyRevision) -> Verifier:
        """Pre-Parse verify of XMCD.

        :param data: Binary data withXMCD to be verified.
        :param family: Device family.
        :return: Verifier of pre-parsed binary data.
        """
        ret = Verifier("Pre-parsed XMCD")
        header = XMCDHeader(family)
        header.parse(data)
        ret.add_child(header.verify())
        return ret

    def verify(self) -> Verifier:
        """Verify XMCD data."""
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

        :param binary: binary image.
        :param offset: Offset of XMCD in binary image.
        :param family: Chip family.
        :raises SPSDKError: If given binary block size is not equal to block size in header
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
        """Get validation schema based on configuration.

        :param config: Valid configuration
        :return: Validation schemas
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config["mem_type"])
        conf_block_type = ConfigurationBlockType.from_label(config["config_type"])
        return cls.get_validation_schemas(family, mem_type, conf_block_type)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Load XMCD object from configuration.

        :param config: Configuration dictionary.
        :return: Initialized XMCD object.
        """
        family = FamilyRevision.load_from_config(config)
        mem_type = MemoryType.from_label(config.get_str("mem_type"))
        config_type = ConfigurationBlockType.from_label(config.get_str("config_type"))

        xmcd_settings = config.get_config("xmcd_settings")

        xmcd = cls(family=family, mem_type=mem_type, config_type=config_type)
        xmcd._registers.load_from_config(xmcd_settings)

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
            fuse_script = FuseScript(self.family, DatabaseManager.XMCD)
        except SPSDKError as exc:
            return f"The CRC hash fuses are not available: {exc.description}"
        return fuse_script.generate_script(self)

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the XMCD.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
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
        """Create the validation schema.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
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

        :return: List of validation schemas for XMCD supported families.
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
        """Generate configuration for selected family.

        :param family: Family description.
        :param mem_type: Used memory type.
        :param config_type: Config type: either simplified or full.
        :return: Template of XMCD Block.
        """
        schemas = XMCD.get_validation_schemas(family, mem_type, config_type)
        return cls._get_config_template(family, schemas)

    @classmethod
    def get_supported_configuration_types(
        cls, family: FamilyRevision, mem_type: MemoryType
    ) -> list[ConfigurationBlockType]:
        """Return list of supported memory interfaces.

        :return: List of supported family interfaces.
        """
        mem_types = get_db(family).get_dict(DatabaseManager.XMCD, "mem_types", default={})
        return [
            ConfigurationBlockType.from_label(block_type)
            for block_type in list(mem_types[mem_type.label].keys())
        ]

    def __repr__(self) -> str:
        return (
            f"XMCD Segment:\n"
            f" Family: {self.family}\n"
            f"Memory type: {self.mem_type.description}\n"
            f"Config type: {self.config_type.description}"
        )

    def __str__(self) -> str:
        return (
            "XMCD Segment:\n"
            f" Family:           {self.family}\n"
            f" Memory type:      {self.mem_type}\n"
            f" Config type:      {self.config_type}\n"
        )
