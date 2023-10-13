#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for TrustZone configuration data."""
import logging
import os
import struct
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.image import TZ_SCH_FILE
from spsdk.utils.database import Database
from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import format_value, load_configuration, value_to_int
from spsdk.utils.schema_validator import CommentedConfig, ValidationSchemas

logger = logging.getLogger(__name__)


class TrustZoneType(Enum):
    """Enum defining various types of TrustZone types."""

    ENABLED = (0x0, "TrustZone enabled with default settings")
    CUSTOM = (0x1, "TrustZone enabled with custom settings")
    DISABLED = (0x2, "Disabled")


class TrustZone:
    """Provide creation of binary data to set up the TrustZone engine in CM-33."""

    PRESET_DIR = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "..", "data", "tz_presets")
    )
    CONFIG_FILE = os.path.join(PRESET_DIR, "database.yaml")

    @classmethod
    def enabled(cls) -> "TrustZone":
        """Alternate constructor for ENABLED type of TrustZone."""
        return cls(tz_type=TrustZoneType.ENABLED)

    @classmethod
    def disabled(cls) -> "TrustZone":
        """Alternate constructor for DISABLED type of TrustZone."""
        return cls(tz_type=TrustZoneType.DISABLED)

    @classmethod
    def custom(
        cls, family: str, customizations: dict, revision: Optional[str] = None
    ) -> "TrustZone":
        """Alternate constructor for CUSTOM type of TrustZone."""
        return cls(
            tz_type=TrustZoneType.CUSTOM,
            family=family,
            revision=revision,
            customizations=customizations,
        )

    @classmethod
    def from_binary(
        cls, family: str, raw_data: bytes, revision: Optional[str] = None
    ) -> "TrustZone":
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
            raise SPSDKError(f"Invalid TrustZone configuration file: {str(exc)}") from exc

    def __init__(
        self,
        tz_type: TrustZoneType = TrustZoneType.ENABLED,
        family: Optional[str] = None,
        revision: Optional[str] = None,
        customizations: Optional[dict] = None,
        raw_data: Optional[bytes] = None,
    ) -> None:
        """Initialize the trustzone."""
        self.type = tz_type
        self.family = family
        self.database = self.load_database()
        self.customs = customizations
        self.revision = revision

        if self.type == TrustZoneType.DISABLED and customizations:
            raise SPSDKError("TrustZone was disabled, can't add trust_zone_data")

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
        database = cls.load_database()
        file_name = database.devices.get_by_name(family).revisions.get(revision).data_file
        if not file_name:
            raise SPSDKValueError(f"Data file for {family} does't exist!")
        return len(load_configuration(os.path.join(TrustZone.PRESET_DIR, file_name))) * 4

    @classmethod
    def get_validation_schemas_family(cls) -> List[Dict[str, Any]]:
        """Create the validation schema just for supported families.

        :return: List of validation schemas for TZ supported families.
        """
        sch_cfg = ValidationSchemas.get_schema_file(TZ_SCH_FILE)
        sch_cfg["tz_family_rev"]["properties"]["family"]["enum"] = cls.get_supported_families()
        return [sch_cfg["tz_family_rev"]]

    @classmethod
    def get_validation_schemas(cls, family: str, revision: str = "latest") -> List[Dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        database = cls.load_database()
        sch_cfg = ValidationSchemas.get_schema_file(TZ_SCH_FILE)
        preset_properties = {}

        try:
            revision_info = database.devices.get_by_name(family).revisions.get(revision)
            assert revision_info.data_file
            presets = load_configuration(
                os.path.join(TrustZone.PRESET_DIR, revision_info.data_file)
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
            sch_cfg["tz_family_rev"]["properties"]["family"]["enum"] = cls.get_supported_families()
            return [sch_cfg["tz_family_rev"], sch_cfg["tz"]]
        except (KeyError, SPSDKError) as exc:
            raise SPSDKError(f"Family {family} or revision {revision} is not supported") from exc

    @classmethod
    def generate_config_template(cls, family: str, revision: str = "latest") -> Dict[str, str]:
        """Generate configuration for selected family.

        :param family: Family description.
        :param revision: Chip revision specification, as default, latest is used.
        :raises SPSDKError: Revision is not supported.
        :return: Dictionary of individual templates (key is name of template, value is template itself).
        """
        ret: Dict[str, str] = {}
        database = cls.load_database()
        if family in cls.get_supported_families():
            try:
                revision_info = database.devices.get_by_name(family).revisions.get(revision)
                revision = revision_info.name
            except (KeyError, SPSDKError) as exc:
                raise SPSDKError(f"Revision {revision} is not supported") from exc

            schemas = cls.get_validation_schemas(family, revision)
            override = {}
            override["family"] = family
            override["revision"] = revision

            yaml_data = CommentedConfig(
                f"Trust Zone Configuration template for {family}.",
                schemas,
                override,
            ).export_to_yaml()
            ret[f"{family}_tz"] = yaml_data

        return ret

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        return f"<TrustZone: type: {self.type} ({TrustZoneType.desc(self.type)})"

    @classmethod
    def load_database(cls) -> Database:
        """Load data from TZ config file."""
        return Database(cls.CONFIG_FILE)

    @classmethod
    def get_supported_families(cls) -> List[str]:
        """Return list of supported families."""
        return Database.get_devices(cls.CONFIG_FILE).device_names

    def get_families(self) -> List[str]:
        """Return list of supported chip families."""
        return self.database.devices.device_names

    def get_revisions(self, family: Optional[str] = None) -> List[str]:
        """Return a list of revisions for given family."""
        actual_family = family or self.family
        assert actual_family
        revisions = self.database.devices.get_by_name(actual_family).revisions
        return [revision.name for revision in revisions]

    def get_latest_revision(self, family: Optional[str] = None) -> str:
        """Return latest revision for given family."""
        actual_family = family or self.family
        assert actual_family
        return self.database.devices.get_by_name(actual_family).revisions.get_latest().name

    def sanitize_revision(self, family: str, revision: Optional[str] = None) -> str:
        """Sanitize revision.

        if the 'revision' is None return the latest revision
        if the 'revision' is provided return it as lower-case
        """
        if not revision or revision.lower() == "latest":
            return self.get_latest_revision(family)
        return revision.lower()

    def _get_preset_file(self) -> str:
        assert self.family
        file_name = (
            self.database.devices.get_by_name(self.family).revisions.get(self.revision).data_file
        )
        assert file_name, f"Data file for {self.family} does't exist!"
        return os.path.join(TrustZone.PRESET_DIR, file_name)

    def _load_presets(self) -> dict:
        """Load default TrustZone settings for given family and revision."""
        presets = load_configuration(self._get_preset_file())
        # Unify the values format
        return {name: format_value(value_to_int(value), 32) for name, value in presets.items()}

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
        logger.debug(str(modifications).replace(", ", "\n"))
        data = self.presets
        data.update(self.customs)
        registers = [value_to_int(item) for item in data.values()]
        # transform data into binary format (little endian, 32b per register)
        return struct.pack(f"<{len(registers)}I", *registers)

    def export(self) -> bytes:
        """Return the TrustZone data as bytes."""
        return self._custom_export() if self.type == TrustZoneType.CUSTOM else bytes()
