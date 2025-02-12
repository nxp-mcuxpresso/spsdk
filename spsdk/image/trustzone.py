#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for TrustZone configuration data."""
import logging
import struct
from typing import Any, Optional

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.misc import format_value, value_to_int
from spsdk.utils.schema_validator import CommentedConfig, update_validation_schema_family
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class TrustZoneType(SpsdkEnum):
    """Enum defining various types of TrustZone types."""

    ENABLED = (0x0, "ENABLED", "TrustZone enabled with default settings")
    CUSTOM = (0x1, "CUSTOM", "TrustZone enabled with custom settings")
    DISABLED = (0x2, "DISABLED", "Disabled")


class TrustZone:
    """Provide creation of binary data to set up the TrustZone engine in CM-33."""

    @classmethod
    def enabled(cls) -> "TrustZone":
        """Alternate constructor for ENABLED type of TrustZone.

        :returns: TrustZone object
        """
        return cls(tz_type=TrustZoneType.ENABLED)

    @classmethod
    def disabled(
        cls,
    ) -> "TrustZone":
        """Alternate constructor for DISABLED type of TrustZone.

        :returns: TrustZone object
        """
        return cls(tz_type=TrustZoneType.DISABLED)

    @classmethod
    def custom(cls, family: str, customizations: dict, revision: str = "latest") -> "TrustZone":
        """Alternate constructor for CUSTOM type of TrustZone."""
        return cls(
            family=family,
            revision=revision,
            tz_type=TrustZoneType.CUSTOM,
            customizations=customizations,
        )

    @classmethod
    def from_binary(cls, family: str, raw_data: bytes, revision: str = "latest") -> "TrustZone":
        """Alternate constructor using existing binary data."""
        return cls(
            family=family,
            revision=revision,
            tz_type=TrustZoneType.CUSTOM,
            raw_data=raw_data,
        )

    @classmethod
    def from_config(cls, config_data: dict[str, Any]) -> "TrustZone":
        """Alternate constructor using configuration data.

        :raises SPSDKError: Invalid configuration file.
        :return: TrustZone class instance.
        """
        try:
            family = config_data["family"]
            revision = config_data.get("revision", "latest")
            presets = config_data["trustZonePreset"]
            return cls.custom(family=family, customizations=presets, revision=revision)
        except (TypeError, SPSDKError) as exc:
            raise SPSDKError(f"Invalid TrustZone configuration file: {str(exc)}") from exc

    def __init__(
        self,
        family: str = "Unknown",
        revision: str = "latest",
        tz_type: TrustZoneType = TrustZoneType.ENABLED,
        customizations: Optional[dict] = None,
        raw_data: Optional[bytes] = None,
    ) -> None:
        """Initialize the trustzone."""
        self.type = tz_type
        self.family = family
        self.customs = customizations

        if self.type == TrustZoneType.DISABLED and customizations:
            raise SPSDKError("TrustZone was disabled, can't add trust_zone_data")

        if self.customs is not None:
            self.type = TrustZoneType.CUSTOM

        if self.type == TrustZoneType.CUSTOM:
            self.presets: dict = DatabaseManager().db.load_db_cfg_file(
                get_db(family, revision).get_file_path(DatabaseManager.TZ, "reg_spec")
            )
            if raw_data:
                self.customs = self._parse_raw_data(raw_data)
            if self.customs is None:
                raise SPSDKError("Need to provide 'customization' parameter")

            if not TrustZone.validate_custom_data(self.presets, self.customs):
                raise SPSDKError(
                    "Invalid register found in customization data:\n"
                    f"{[item for item in self.customs if item not in self.presets]}"
                )

    @classmethod
    def get_preset_data_size(cls, family: str, revision: str = "latest") -> int:
        """Get size of preset data in binary form.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKValueError: Family or revision is not supported.
        :return: Size of TZ data.
        """
        database = get_db(family, revision)
        data = DatabaseManager().db.load_db_cfg_file(
            database.get_file_path(DatabaseManager.TZ, "reg_spec")
        )
        return len(data) * 4

    @classmethod
    def get_validation_schemas_family(cls) -> list[dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for TZ supported families.
        """
        sch_cfg = get_schema_file("general")["family"]
        update_validation_schema_family(sch_cfg["properties"], cls.get_supported_families())
        return [sch_cfg]

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.TZ)
        sch_family = get_schema_file("general")["family"]
        preset_properties = {}

        try:
            database = get_db(family, revision)
            presets = DatabaseManager().db.load_db_cfg_file(
                database.get_file_path(DatabaseManager.TZ, "reg_spec")
            )
            for key, value in presets.items():
                preset_properties[key] = {
                    "type": ["string", "number"],
                    "title": "TZ Preset",
                    "description": f"Preset for {key}",
                    "format": "number",
                    "template_value": f"{value}",
                }
            if "patternProperties" in sch_cfg["tz"]["properties"]["trustZonePreset"].keys():
                sch_cfg["tz"]["properties"]["trustZonePreset"].pop("patternProperties")
            sch_cfg["tz"]["properties"]["trustZonePreset"]["properties"] = preset_properties
            update_validation_schema_family(
                sch_family["properties"], cls.get_supported_families(), family, revision
            )
            return [sch_family, sch_cfg["tz"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or revision {revision} is not supported") from exc

    @classmethod
    def generate_config_template(cls, family: str, revision: str = "latest") -> dict[str, str]:
        """Generate configuration for selected family.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Revision is not supported.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        ret: dict[str, str] = {}
        schemas = cls.get_validation_schemas(family, revision)

        yaml_data = CommentedConfig(
            f"Trust Zone Configuration template for {family}.", schemas
        ).get_template()
        ret[f"{family}_tz"] = yaml_data

        return ret

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"<TrustZone: type: {self.type} ({self.type.description})"

    @staticmethod
    def get_supported_families() -> list[str]:
        """Return list of supported families."""
        return get_families(DatabaseManager.TZ)

    def _parse_raw_data(self, raw_data: bytes) -> dict:
        """Parse raw data into 'customizations' format."""
        if len(self.presets) > len(raw_data) // 4:
            raise SPSDKError(
                "Trustzone binary file has incorrect raw_data length\n"
                f"Expected: {len(self.presets)}, Got: {len(raw_data) // 4}"
            )

        if len(self.presets) != len(raw_data) // 4:
            logger.warning(
                "Trustzone binary file has incorrect raw_data length\n"
                f"Expected: {len(self.presets)}, Got: {len(raw_data) // 4}"
            )

        registers = struct.unpack(f"<{len(self.presets)}L", raw_data[: len(self.presets) * 4])
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
        modifications = set(self.customs.items()) - set(self.presets.items())
        logger.info(f"{len(modifications)} modifications provided")
        if (
            logger.getEffectiveLevel() <= logging.DEBUG
        ):  # Do this additional condition to avoid creating of huge strings used for debug
            logger.debug(str(modifications).replace(", ", "\n"))
        data = self.presets
        data.update(self.customs)
        registers = [value_to_int(item) for item in data.values()]
        # transform data into binary format (little endian, 32b per register)
        return struct.pack(f"<{len(registers)}I", *registers)

    def export(self) -> bytes:
        """Return the TrustZone data as bytes."""
        return self._custom_export() if self.type == TrustZoneType.CUSTOM else bytes()
