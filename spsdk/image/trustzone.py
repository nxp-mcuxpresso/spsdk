#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for TrustZone configuration data."""
import json
import logging
import os
import struct
from typing import Any, Dict, List, Optional

from spsdk import SPSDKError
from spsdk.apps.utils import load_configuration
from spsdk.image import TZ_SCH_FILE
from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import format_value, value_to_int
from spsdk.utils.schema_validator import ConfigTemplate, ValidationSchemas

logger = logging.getLogger(__name__)


class TrustZoneType(Enum):
    """Enum defining various types of TrustZone types."""

    ENABLED = (0x00, "TrustZone enabled with default settings")
    CUSTOM = (0x20, "TrustZone enabled with custom settings")
    DISABLED = (0x40, "Disabled")


class TrustZone:
    """Provide creation of binary data to set up the TrustZone engine in CM-33."""

    PRESET_DIR = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "data", "tz_presets")
    )
    CONFIG_FILE = os.path.join(PRESET_DIR, "database.json")

    @classmethod
    def enabled(cls) -> "TrustZone":
        """Alternate constructor for ENABLED type of TrustZone."""
        return cls(tz_type=TrustZoneType.ENABLED)

    @classmethod
    def disabled(cls) -> "TrustZone":
        """Alternate constructor for DISABLED type of TrustZone."""
        return cls(tz_type=TrustZoneType.DISABLED)

    @classmethod
    def custom(cls, family: str, customizations: dict, revision: str = None) -> "TrustZone":
        """Alternate constructor for CUSTOM type of TrustZone."""
        return cls(
            tz_type=TrustZoneType.CUSTOM,
            family=family,
            revision=revision,
            customizations=customizations,
        )

    @classmethod
    def from_binary(cls, family: str, raw_data: bytes, revision: str = None) -> "TrustZone":
        """Alternate constructor using existing binary data."""
        return cls(
            tz_type=TrustZoneType.CUSTOM,
            family=family,
            revision=revision,
            raw_data=raw_data,
        )

    @classmethod
    def from_config(cls, config_data: Dict[str, Any]) -> "TrustZone":
        """Alternate constructor using configuration data.

        :raises SPSDKError: Invalid configuration file.
        :return: TrustZone class instance.
        """
        try:
            family = config_data["family"]
            revision = config_data.get("revision")
            presets = config_data["trustZonePreset"]
            return cls.custom(family=family, customizations=presets, revision=revision)
        except (TypeError, SPSDKError) as exc:
            raise SPSDKError("Invalid TrustZone configuration file.") from exc

    def __init__(
        self,
        tz_type: TrustZoneType = TrustZoneType.ENABLED,
        family: str = None,
        revision: str = None,
        customizations: dict = None,
        raw_data: bytes = None,
    ) -> None:
        """Initialize the trustzone."""
        self.type = tz_type
        self.family: Optional[str] = family
        self.config: dict = self.load_config_file()
        self.customs: Optional[dict] = customizations
        self.revision: Optional[str] = revision

        if self.type == TrustZoneType.DISABLED and customizations:
            raise SPSDKError("TrustZone was disabled, can't add trust_zone_data")

        # TODO: Should empty customs qualifies for CUSTOM TZ type???
        if self.customs is not None:
            self.type = TrustZoneType.CUSTOM

        if self.type == TrustZoneType.CUSTOM:
            if not self.family:
                raise SPSDKError("Need to provide 'family' parameter")
            self.family = self.family.lower()
            if self.family not in self.get_families():
                raise SPSDKError(f"Chip family '{self.family}' is not supported\n")
            self.revision = self.sanitize_revision(self.family, self.revision)
            if self.revision not in self.get_revisions():
                raise SPSDKError(
                    f"Revision '{self.revision}' is not supported on family '{self.family}'\n"
                )

            self.presets: dict = self._load_presets()
            if raw_data:
                self.customs = self._parse_raw_data(raw_data)
            if self.customs is None:
                raise SPSDKError("Need to provide 'customization' parameter")

            if not TrustZone.validate_custom_data(self.presets, self.customs):
                raise SPSDKError(
                    "Invalid register found in customization data:\n"
                    "%s" % [item for item in self.customs if item not in self.presets]
                )

    @classmethod
    def get_validation_schemas(cls) -> List[Dict[str, Any]]:
        """Create the validation schema.

        :return: List of validation schemas.
        """
        sch_cfg = ValidationSchemas.get_schema_file(TZ_SCH_FILE)
        return [sch_cfg["tz"]]

    @classmethod
    def generate_config_template(cls, family: str) -> Dict[str, str]:
        """Generate configuration for selected family.

        :param family: Family description.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        ret: Dict[str, str] = {}

        config_file = cls.load_config_file()
        schemas = cls.get_validation_schemas()
        override = {}
        override["family"] = family
        override["revisions"] = config_file[family]["latest"]
        preset_properties = {}

        presets = load_configuration(
            os.path.join(
                TrustZone.PRESET_DIR, config_file[family]["revisions"][override["revisions"]]
            )
        )
        for key, value in presets.items():
            preset_properties[key] = {
                "type": ["string", "number"],
                "title": "TZ Preset",
                "description": f"Preset for {key}",
                "format": "number",
                "template_value": f"{value}",
            }
        schemas[0]["properties"]["trustZonePreset"]["properties"] = preset_properties

        yaml_data = ConfigTemplate(
            f"Trust Zone Configuration template for {family}.",
            schemas,
            override,
        ).export_to_yaml()
        ret[f"{family}_tz"] = yaml_data

        return ret

    def __str__(self) -> str:
        return f"<TrustZone: type: {self.type} ({TrustZoneType.desc(self.type)})"

    @classmethod
    def load_config_file(cls) -> dict:
        """Load data from TZ config file."""
        with open(cls.CONFIG_FILE) as f:
            return json.load(f)

    def get_families(self) -> list:
        """Return list of supported chip families."""
        return list(self.config.keys())

    def get_revisions(self, family: str = None) -> list:
        """Return a list of revisions for given family."""
        return list(self.config[family or self.family]["revisions"].keys())

    def get_latest_revision(self, family: str = None) -> str:
        """Return latest revision for given family."""
        return self.config[family or self.family]["latest"]

    def sanitize_revision(self, family: str, revision: Optional[str]) -> str:
        """Sanitize revision.

        if the 'revision' is None return the latest revision
        if the 'revision' is provided return it as lower-case
        """
        return revision.lower() if revision else self.get_latest_revision(family)

    def _get_preset_file(self) -> str:
        return os.path.join(
            TrustZone.PRESET_DIR, self.config[self.family]["revisions"][self.revision]
        )

    def _load_presets(self) -> dict:
        """Load default TrustZone settings for given family and revision."""
        with open(self._get_preset_file()) as preset_file:
            return json.load(preset_file)

    def _parse_raw_data(self, raw_data: bytes) -> dict:
        """Parse raw data into 'customizations' format."""
        if len(self.presets) != len(raw_data) // 4:
            raise SPSDKError(
                "Trustzone binary file has incorrect raw_data length\n"
                f"Expected: {len(self.presets)}, Got: {len(raw_data) // 4}"
            )

        registers = struct.unpack(f"<{len(raw_data) // 4}L", raw_data)
        customs = {name: format_value(registers[i], 32) for i, name in enumerate(self.presets)}
        return customs

    @staticmethod
    def validate_custom_data(data: dict, customizations: dict) -> bool:
        """Check whether all register names in custom data are valid (present in presets)."""
        return all(item in data for item in customizations)

    def _custom_export(self) -> bytes:
        if self.presets is None:
            raise SPSDKError("Preset data not present")
        if self.customs is None:
            raise SPSDKError("Data not present")
        logger.info(f"{len(self.presets)} registers loaded from defaults")
        logger.debug(self.presets)
        logger.info(f"{len(self.customs)} modifications provided")
        logger.debug(self.customs)
        data = self.presets
        data.update(self.customs)
        registers = [value_to_int(item) for item in data.values()]
        # transform data into binary format (little endian, 32b per register)
        return struct.pack(f"<{len(registers)}I", *registers)

    def export(self) -> bytes:
        """Return the TrustZone data as bytes."""
        return self._custom_export() if self.type == TrustZoneType.CUSTOM else bytes()
