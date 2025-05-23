#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for TrustZone configuration data."""
import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.abstract_features import FeatureBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_families, update_validation_schema_family
from spsdk.utils.misc import Endianness
from spsdk.utils.registers import Registers
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class TrustZoneType(SpsdkEnum):
    """Enum defining various types of TrustZone types."""

    ENABLED = (0x0, "ENABLED", "TrustZone enabled with default settings")
    CUSTOM = (0x1, "CUSTOM", "TrustZone enabled with custom settings")
    DISABLED = (0x2, "DISABLED", "Disabled")


class TrustZone(FeatureBaseClass):
    """Provide creation of binary data to set up the TrustZone engine in CM-33."""

    FEATURE = DatabaseManager.TZ

    def __init__(self, family: FamilyRevision) -> None:
        """Initialize the trustzone."""
        self.family = family
        if family.name not in [x.name for x in get_families(DatabaseManager.TZ)]:
            raise SPSDKValueError(f"The {family} family doesn't support TrustZone")
        self.regs = Registers(family, DatabaseManager.TZ, base_endianness=Endianness.LITTLE)

    @classmethod
    def get_preset_data_size(cls, family: FamilyRevision) -> int:
        """Get size of preset data in binary form.

        :param family: Family description.
        :raises SPSDKValueError: Family or revision is not supported.
        :return: Size of TZ data.
        """
        return len(TrustZone(family))

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Create the validation schema.

        :param family: Family description.
        :raises SPSDKError: Family or revision is not supported.
        :return: List of validation schemas.
        """
        sch_cfg = get_schema_file(DatabaseManager.TZ)["tz"]
        sch_family = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch_family["properties"], cls.get_supported_families(), family
        )

        sch_cfg["properties"]["trustZonePreset"] = cls(family).regs.get_validation_schema()
        return [sch_family, sch_cfg]

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Alternate constructor using configuration data.

        :raises SPSDKError: Invalid configuration file.
        :return: TrustZone class instance.
        """
        family = FamilyRevision.load_from_config(config)
        ret = cls(family)
        ret.regs.load_from_config(config.get_config("trustZonePreset"))
        return ret

    def get_config(self, data_path: str = "./") -> Config:
        """Create configuration of the TrustZOne.

        :param data_path: Path to store the data files of configuration.
        :return: Configuration dictionary.
        """
        ret = Config()

        ret["family"] = self.family.name
        ret["revision"] = self.family.revision
        ret["tzpOutputFile"] = data_path + f"{self.family.name}_tz.yaml"
        ret["trustZonePreset"] = dict(self.regs.get_config())

        return ret

    @property
    def is_customized(self) -> bool:
        """The trustzone has customized values.

        :return: True if the TrustZone is customized, False otherwise.
        """
        return not self.regs.has_reset_value

    def __len__(self) -> int:
        return len(self.regs) * 4

    def __repr__(self) -> str:
        return self.__str__()

    def __str__(self) -> str:
        if self.is_customized:
            return "TrustZone with customized values."
        return "TrustZone with default values(Just enabled)."

    def export(self) -> bytes:
        """Return the TrustZone data as bytes."""
        return self.regs.export()

    @classmethod
    def parse(cls, data: bytes, family: Optional[FamilyRevision] = None) -> Self:
        """Parse object from bytes array.

        :param data: Bytes array containing TrustZone configuration
        :param family: Optional family revision for parsing
        :raises SPSDKValueError: If family is not provided
        :return: Parsed TrustZone instance
        """
        if family is None:
            raise SPSDKValueError("The family parameter must be defined")
        ret = cls(family=family)
        ret.regs.parse(data)
        return ret
