#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""Parser of BD configuration."""

from collections import UserDict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKKeyError


@dataclass
class ImageConfig:
    """Represent parsed image configuration including options and sections."""

    elf_file: str
    options: "ConfigOptions"
    sections: List["SectionConfig"]

    @staticmethod
    def parse(data: Dict[str, Any]) -> "ImageConfig":
        """Parse config from dictionary.

        :param data: Configuration data to be parsed.
        """
        options = ConfigOptions.parse(data["options"])
        sections: List = []
        for section in data["sections"]:
            sections.append(SectionConfig.parse(section))
        return ImageConfig(elf_file=data["sources"]["elfFile"], options=options, sections=sections)

    def get_section(self, section_index: int) -> Optional["SectionConfig"]:
        """Get config section by section id.

        :param section_index: Section with index to be retrieved
        """
        for section in self.sections:
            if section.index == section_index:
                return section
        return None


@dataclass
class ConfigOptions:
    """Dataclass holding configuration options."""

    flags: int
    start_address: int
    ivt_offset: int
    initial_load_size: int
    entrypoint_address: int
    signature_timestamp: Optional[datetime] = None
    dcd_file_path: Optional[str] = None
    xmcd_file_path: Optional[str] = None

    _FIELD_MAPPING = {
        "flags": "flags",
        "startaddress": "start_address",
        "ivtoffset": "ivt_offset",
        "initialloadsize": "initial_load_size",
        "entrypointaddress": "entrypoint_address",
        "signaturetimestamp": "signature_timestamp",
        "dcdfilepath": "dcd_file_path",
        "xmcdfilepath": "xmcd_file_path",
    }

    @staticmethod
    def parse(options: Dict[str, Any]) -> "ConfigOptions":
        """Parse config options from dictionary.

        :param options: Options to be parsed
        :raises SPSDKKeyError: If unexpected key is present
        """
        params = {}
        for opt in options:
            if opt.lower() not in ConfigOptions._FIELD_MAPPING:
                raise SPSDKKeyError(f"Unexpected option field {opt}")
            value = options[opt]
            if opt.lower() == "signaturetimestamp":
                value = datetime.strptime(value, "%d/%m/%Y %H:%M:%S").replace(tzinfo=timezone.utc)
            params[ConfigOptions._FIELD_MAPPING[opt.lower()]] = value
        return ConfigOptions(**params)


class CaseInsensitiveDict(UserDict):
    """Case insensitive dictionary."""

    def __getitem__(self, key: str) -> Any:
        for item in self:
            if isinstance(item, str) and item.lower() == key.lower():
                return self.data[item]
        raise SPSDKKeyError(f"The key {key} was not found.")


@dataclass
class SectionConfig:
    """Dataclass holding single section data."""

    index: int
    options: CaseInsensitiveDict

    @staticmethod
    def parse(section: Dict[str, Any]) -> "SectionConfig":
        """Parse config section from dictionary.

        :param section: Section to be parsed
        """
        index = int(section["section_id"])
        options = CaseInsensitiveDict((key, d[key]) for d in section["options"] for key in d)
        return SectionConfig(index=index, options=options)
