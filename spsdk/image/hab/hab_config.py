#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Parser of BD configuration."""

from collections import UserDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKKeyError, SPSDKValueError
from spsdk.image.hab.commands.commands_enum import SecCommand
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.images import BinaryImage


@dataclass
class HabConfig:
    """Represent parsed image configuration including options and sections."""

    app_image: BinaryImage
    options: "OptionsConfig"
    commands: "CommandsConfig"

    @classmethod
    def load_from_config(
        cls, data: dict[str, Any], search_paths: Optional[list[str]] = None
    ) -> Self:
        """Parse config from dictionary.

        :param data: Configuration data to be parsed.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        elf_binary = BinaryImage.load_binary_image(
            data["sources"]["elfFile"],
            search_paths=search_paths,
        )
        options = OptionsConfig.load_from_config(data)
        commands = CommandsConfig.load_from_config(data)
        return cls(app_image=elf_binary, options=options, commands=commands)


class CommandOptions(UserDict):
    """Case insensitive dictionary."""

    def __getitem__(self, key: str) -> Any:
        for item in self:
            if isinstance(item, str) and item.lower() == key.lower():
                return self.data[item]
        raise SPSDKKeyError(f"The key {key} was not found.")

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Get an item from dictionary, return default if given key does not exist.

        :param key: Case-insensitive dictionary key
        :param default: Default if given key is not present
        """
        try:
            return self[key]
        except SPSDKKeyError:
            return default


@dataclass
class CommandConfig:
    """Configuration of single command."""

    index: int
    params: CommandOptions


@dataclass
class CommandsConfig(list[CommandConfig]):
    """Dataclass holding commands data."""

    @classmethod
    def load_from_config(cls, config: dict[str, Any]) -> Self:
        """Parse command config from HAB configuration.

        :param config: HAB configuration as dictionary
        """
        command_cfg = cls()
        for section in config.get("sections", []):
            # Section 0 is a default section for plain image, in reality there is no section there.
            # This should be fixed in BD lexer
            if section["section_id"] == 0:
                continue
            params = CommandOptions((key, d[key]) for d in section["options"] for key in d)
            command_cfg.append(CommandConfig(index=section["section_id"], params=params))
        return command_cfg

    def get_command_params(self, command: SecCommand) -> CommandOptions:
        """Get parameters of single command.

        :param command: Command object
        :raises SPSDKError: If command with given index does not exist
        """
        cmd = next((x for x in self if x.index == command.tag), None)
        if cmd:
            return cmd.params
        raise SPSDKValueError(f"Command with index {command.tag} does not exist.")

    def contains(self, key: SecCommand) -> bool:
        """Returns true if the object contains a command of specific type, false otherwise."""
        return bool(next((x for x in self if x.index == key.tag), None))


@dataclass
class OptionsConfig:
    """Dataclass holding configuration options."""

    flags: int
    start_address: int
    boot_device: Optional[str] = None
    family: Optional[str] = None
    ivt_offset: Optional[int] = None
    initial_load_size: Optional[int] = None
    entrypoint_address: Optional[int] = None
    signature_timestamp: Optional[datetime] = None
    dcd_file_path: Optional[str] = None
    xmcd_file_path: Optional[str] = None

    _FIELD_MAPPING = {
        "flags": "flags",
        "bootdevice": "boot_device",
        "family": "family",
        "startaddress": "start_address",
        "ivtoffset": "ivt_offset",
        "initialloadsize": "initial_load_size",
        "entrypointaddress": "entrypoint_address",
        "signaturetimestamp": "signature_timestamp",
        "dcdfilepath": "dcd_file_path",
        "xmcdfilepath": "xmcd_file_path",
    }

    @classmethod
    def load_from_config(cls, config: dict[str, dict]) -> Self:
        """Parse options config from HAB configuration.

        :param config: HAB configuration as dictionary
        """
        params: dict[str, Any] = {}
        for name, value in config["options"].items():
            if name.lower() not in cls._FIELD_MAPPING:
                raise SPSDKKeyError(f"Unexpected option field {name}")
            if name.lower() == "signaturetimestamp":
                value = datetime.strptime(value, "%d/%m/%Y %H:%M:%S").replace(tzinfo=timezone.utc)
            params[cls._FIELD_MAPPING[name.lower()]] = value
        return cls(**params)

    def get_ivt_offset(self) -> int:
        """Get IVT offset."""
        if self.ivt_offset is not None:
            return self.ivt_offset
        if not (self.family and self.boot_device):
            raise SPSDKValueError(
                "Either 'ivtOffset' or 'family' and 'bootDevice' options must be specified."
            )
        db = get_db(device=self.family)
        return db.get_int(
            DatabaseManager.BOOTABLE_IMAGE,
            ["mem_types", self.boot_device, "segments", "hab_container"],
        )

    def get_initial_load_size(self) -> int:
        """Get initial load size."""
        if self.initial_load_size is not None:
            return self.initial_load_size
        if not (self.family and self.boot_device):
            raise SPSDKValueError(
                "Either 'initialLoadSize' or 'family' and 'bootDevice' options must be specified."
            )
        db = get_db(device=self.family)
        return db.get_int(
            DatabaseManager.HAB,
            ["mem_types", self.boot_device, "initial_load_size"],
        )
