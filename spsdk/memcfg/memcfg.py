#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for Memory configuration (known as a flash configuration option words)."""


import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.abstract import BaseClass
from spsdk.utils.database import (
    DatabaseManager,
    get_common_data_file_path,
    get_db,
    get_device,
    get_families,
    get_schema_file,
)
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family

logger = logging.getLogger(__name__)


@dataclass
class Memory:
    """Memory dataclass."""

    name: str
    interface: str
    manufacturer: str
    peripheral: str
    option_words: list = field(default_factory=list)
    tested: bool = False

    def get_option_words_string(self) -> str:
        """Get option words in string format.

        :return: Option words in string
        """
        option_words_str = f"Opt0: 0x{self.option_words[0]:08X}"
        for ow_i, ow in enumerate(self.option_words[1:]):
            option_words_str += f", Opt{ow_i+1}: 0x{ow:08X}"
        return option_words_str


class MemoryConfig(BaseClass):
    """General memory configuration class."""

    # Supported peripherals and their region numbers
    PERIPHERALS: list[str] = list(
        DatabaseManager().db.get_defaults(DatabaseManager.MEMCFG)["peripherals"].keys()
    )
    SUPPORTS_FCB_CREATION = [9]

    def __init__(
        self,
        family: str,
        peripheral: str,
        revision: str = "latest",
        interface: Optional[str] = None,
    ) -> None:
        """Initialize memory configuration class.

        :param family: Chip family
        :param peripheral: Peripheral name
        :param revision: Chip revision
        :param interface: Memory interface
        """
        self.family = family
        self.db = get_db(family, revision)
        self.revision = self.db.name
        if peripheral not in self.get_supported_peripherals(self.family):
            raise SPSDKValueError(f"The {peripheral} is not supported by {self.family}")
        self.peripheral = peripheral
        self.regs = Registers(
            family=self.family,
            feature=DatabaseManager.MEMCFG,
            base_key=["peripherals", peripheral],
            revision=revision,
            base_endianness=Endianness.LITTLE,
        )
        self.interface = interface or ""

    def __repr__(self) -> str:
        """Representation string."""
        return f"Memory configuration for {self.family}, {self.peripheral}"

    def __str__(self) -> str:
        """Representation string."""
        return (
            self.__repr__()
            + f"\n Used interface is {self.interface} and option words are {self.option_words}"
        )

    def get_peripheral(self, peripheral: Optional[str]) -> str:
        """Get peripheral name, priority has from parameter as a backup is class member.

        :param peripheral: Memory peripheral;
        :raises SPSDKValueError: Peripheral is not defined
        :return: Peripheral name
        """
        ret = peripheral or self.peripheral
        if not ret:
            raise SPSDKValueError("Peripheral is not specified")
        return ret

    @property
    def option_words(self) -> list[int]:
        """Get option words."""
        ret: list[int] = []
        count_to_export = self.option_words_count
        for i, reg in enumerate(self.regs.get_registers()):
            if i >= count_to_export:
                break
            ret.append(reg.get_value())
        return ret

    @property
    def option_words_count(self) -> int:
        """Get current count of option words."""
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

    def peripheral_instances(self, peripheral: Optional[str] = None) -> list[int]:
        """Get peripheral instances."""
        return self.db.get_list(
            DatabaseManager.MEMCFG,
            ["peripherals", self.get_peripheral(peripheral), "instances"],
            [],
        )

    def peripheral_cnt(self, peripheral: Optional[str] = None) -> int:
        """Get count of peripheral instances."""
        return len(
            self.db.get_list(
                DatabaseManager.MEMCFG,
                ["peripherals", self.get_peripheral(peripheral), "instances"],
                [],
            )
        )

    def get_validation_schemas(self, peripheral: Optional[str] = None) -> list[dict[str, Any]]:
        """Create the validation schema for one peripheral.

        :param peripheral: External memory peripheral.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.MEMCFG)
        sch_family = get_schema_file("general")["family"]
        peripheral_loc = self.get_peripheral(peripheral)
        if peripheral_loc not in self.get_supported_peripherals(self.family):
            raise SPSDKValueError(
                f"The {peripheral_loc} peripheral is not supported by {self.family}"
            )
        update_validation_schema_family(
            sch_family["properties"], self.get_supported_families(), self.family
        )
        sch_cfg["base"]["properties"]["peripheral"]["template_value"] = peripheral_loc
        sch_cfg["base"]["properties"]["peripheral"]["enum"] = self.get_supported_peripherals(
            self.family
        )

        sch_cfg["settings"]["properties"]["settings"][
            "properties"
        ] = self.regs.get_validation_schema()["properties"]
        return [sch_family, sch_cfg["base"], sch_cfg["settings"]]

    @classmethod
    def parse(  # type: ignore# type: ignore # pylint: disable=arguments-differ
        cls,
        data: bytes,
        family: str,
        peripheral: str,
        revision: str = "latest",
        interface: Optional[str] = None,
    ) -> Self:
        """Parse the option words to configuration.

        :param data: Option words in bytes
        :param family: Chip family
        :param peripheral: Peripheral name
        :param revision: Chip revision
        :param interface: Memory interface
        :return: Dictionary with parsed configuration.
        """
        ret = cls(family=family, peripheral=peripheral, revision=revision, interface=interface)
        ret.regs.parse(data)
        return ret

    @staticmethod
    def option_words_to_bytes(option_words: list[int]) -> bytes:
        """Convert option words to bytes.

        :param option_words: Option words list
        :return: Bytes with option words
        """
        ow_bytes = bytes()
        for ow in option_words:
            ow_bytes += ow.to_bytes(4, Endianness.LITTLE.value)
        return ow_bytes

    def export(self) -> bytes:
        """Export option words to bytes."""
        return self.regs.export()

    def get_config(self) -> dict[str, Any]:
        """Get class configuration.

        :return: Dictionary with configuration of the class.
        """
        ret: dict[str, Any] = {}
        ret["family"] = self.family
        ret["revision"] = self.revision
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

    @staticmethod
    def get_supported_peripherals(family: str) -> list[str]:
        """Get list of supported peripherals by the family."""
        ret = []
        for peripheral, settings in (
            get_db(family).get_dict(DatabaseManager.MEMCFG, "peripherals").items()
        ):
            if len(settings["instances"]):
                ret.append(peripheral)
        return ret

    @staticmethod
    def get_peripheral_instances(family: str, peripheral: str) -> list[int]:
        """Get peripheral instances."""
        return get_db(family).get_list(
            DatabaseManager.MEMCFG,
            ["peripherals", peripheral, "instances"],
            [],
        )

    @staticmethod
    def get_validation_schemas_base() -> list[dict[str, Any]]:
        """Create the validation schema for MemCfg class bases.

        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.MEMCFG)
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], MemoryConfig.get_supported_families()
        )
        return [sch_family, sch_cfg["base"]]

    @staticmethod
    def get_option_words_string(option_words: list[int]) -> str:
        """Get option words in string format.

        :param option_words: List of option words.
        :return: Option words in string
        """
        option_words_str = f"0x{option_words[0]:08X}"
        for ow in option_words[1:]:
            option_words_str += f", 0x{ow:08X}"
        return option_words_str

    def get_yaml(self) -> str:
        """Parse the option words to YAML config file.

        :return: YAML file content with configuration.
        """
        cfg = self.get_config()
        schemas = self.get_validation_schemas()
        return CommentedConfig(
            (
                f"Configuration created for {self.family}, {self.peripheral} from these \n"
                f"option words: {self.get_option_words_string(self.option_words)}"
            ),
            schemas=schemas,
        ).get_config(cfg)

    @classmethod
    def load_config(cls, config: dict[str, Any]) -> Self:
        """Load Yaml configuration and decode.

        :param config: Memory configuration dictionary.
        """
        family = config["family"]
        revision = config.get("revision", "latest")
        peripheral = config["peripheral"]
        interface = config["interface"]
        regs = Registers(
            family=family,
            feature=DatabaseManager.MEMCFG,
            base_key=["peripherals", peripheral],
            revision=revision,
            base_endianness=Endianness.LITTLE,
        )
        regs.load_yml_config(config["settings"])

        ret = cls(family=family, revision=revision, peripheral=peripheral, interface=interface)

        ret.regs.load_yml_config(config["settings"])
        return ret

    def create_blhost_batch_config(
        self,
        instance: Optional[int] = None,
        fcb_output_name: Optional[str] = None,
        secure_addresses: bool = False,
    ) -> str:
        """Create BLHOST script that configure memory.

        Optionally the script can force create of FCB on chip and read back it

        :param instance: Optional peripheral instance
        :param fcb_output_name: The name of generated FCB block file, defaults to False
        :param secure_addresses: When defined the script will use secure addresses instead of normal.
        :return: BLHOST batch file that configure the external memory
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
        if instance is not None and ((not instance in instances) or not runtime_instance):
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

            if not mem_region in self.SUPPORTS_FCB_CREATION:
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
    def get_peripheral_cnt(family: str, peripheral: str) -> int:
        """Get count of peripheral instances."""
        return len(
            get_db(family).get_list(
                DatabaseManager.MEMCFG,
                ["peripherals", peripheral, "instances"],
                [],
            )
        )

    @staticmethod
    def get_known_memories(family: str, peripheral: Optional[str] = None) -> list[Memory]:
        """Get all known supported memory configurations.

        :param family: The chip family
        :param peripheral: Restrict results just for this one peripheral if defined
        :returns: List of memories
        """
        memories = MemoryConfig.get_all_known_memories(peripheral)
        return [
            memory
            for memory in memories
            if MemoryConfig.get_peripheral_cnt(family, memory.peripheral)
        ]

    @staticmethod
    def get_all_known_memories(peripheral: Optional[str] = None) -> list[Memory]:
        """Get all known supported memory configurations.

        :param peripheral: Restrict results just for this one peripheral if defined
        :returns: List of memories
        """
        flash_chips: dict[str, dict[str, dict[str, dict]]] = DatabaseManager().db.load_db_cfg_file(
            get_common_data_file_path(os.path.join("memcfg", "memcfg_data.yaml"))
        )["flash_chips"]
        ret = []
        peripherals = [peripheral] if peripheral else MemoryConfig.PERIPHERALS
        for p in peripherals:
            if p not in flash_chips:
                continue
            for man_name, chip_names in flash_chips[p].items():
                for chip_name, interfaces in chip_names.items():
                    for iface_name, iface_cfg in interfaces.items():
                        memory = Memory(
                            peripheral=p,
                            manufacturer=man_name,
                            interface=iface_name,
                            name=chip_name,
                            option_words=iface_cfg.get("option_words"),
                            tested=iface_cfg.get("tested", False),
                        )
                        ret.append(memory)
        return ret

    @staticmethod
    def get_known_chip_peripheral(chip_name: str) -> str:
        """Get peripheral for one chip from database.

        :param chip_name: Chip name to look for
        :returns: The peripheral name.
        """
        flash_chips: dict[
            str, dict[str, dict[str, dict[str, list[int]]]]
        ] = DatabaseManager().db.load_db_cfg_file(
            get_common_data_file_path(os.path.join("memcfg", "memcfg_data.yaml"))
        )[
            "flash_chips"
        ]
        for peripheral, man_db in flash_chips.items():
            for _, chips in man_db.items():
                if chip_name in chips:
                    return peripheral
        raise SPSDKValueError(f"Unknown flash memory chip name: {chip_name}")

    @staticmethod
    def get_known_chip_memory(
        peripheral: str,
        chip_name: str,
        interface: str,
    ) -> Memory:
        """Get option words for one chip from database.

        :param peripheral: Peripheral used to communicate with chip
        :param chip_name: Chip name to look for
        :param interface: Chip communication interface
        :returns: The List of option words.
        """
        all_memories = MemoryConfig.get_all_known_memories(peripheral)
        try:
            return next(
                (
                    memory
                    for memory in all_memories
                    if memory.name == chip_name and memory.interface == interface
                )
            )
        except StopIteration as e:
            raise SPSDKValueError(
                f"Unknown flash memory chip name: {chip_name} or interface {interface}"
            ) from e

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get the list of supported families.

        :return: List of family names that support memory configuration.
        """
        return get_families(DatabaseManager.MEMCFG)
