#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK IPED (Inline PRINCE Encryption/Decryption) factory module.

This module provides the ``Iped`` factory class that dispatches to the correct
IPED implementation based on the ``iped_version`` database key:

- **Version 1** (``IpedV1``): Tagged ELE configuration structure (i.MX943).
- **Version 2** (``IpedV2``): XSPI register-image table format.

For backward compatibility, ``IpedContext`` and ``IpedMode`` are re-exported from
the V2 module. Use ``Iped.load_from_config()`` or ``Iped.get_validation_schemas()``
for version-agnostic access.
"""

import logging
from typing import Any

from spsdk.exceptions import SPSDKValueError
from spsdk.image.iped.iped_v1 import IpedV1, IpedV1Region
from spsdk.image.iped.iped_v2 import IpedContext, IpedMode, IpedV2
from spsdk.utils.abstract_features import ConfigBaseClass
from spsdk.utils.config import Config
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families

__all__ = ["Iped", "IpedContext", "IpedMode", "IpedV1", "IpedV1Region", "IpedV2"]

logger = logging.getLogger(__name__)

# IPED version constants
IPED_VERSION_V1 = 1
IPED_VERSION_V2 = 2

# Map version numbers to implementation classes
_IPED_CLASSES: dict[int, type[IpedV1] | type[IpedV2]] = {
    IPED_VERSION_V1: IpedV1,
    IPED_VERSION_V2: IpedV2,
}


def _get_iped_version(family: FamilyRevision) -> int:
    """Get IPED version for the given family from the database.

    :param family: Target family.
    :return: IPED version number (1 or 2).
    """
    db = get_db(family)
    return db.get_int(DatabaseManager.IPED, "iped_version")


def _get_iped_class(family: FamilyRevision) -> type[IpedV1] | type[IpedV2]:
    """Get the IPED implementation class for the given family.

    :param family: Target family.
    :raises SPSDKValueError: If the IPED version is not supported.
    :return: IPED class (IpedV1 or IpedV2).
    """
    version = _get_iped_version(family)
    cls = _IPED_CLASSES.get(version)
    if cls is None:
        raise SPSDKValueError(
            f"Unsupported IPED version {version} for family {family}. "
            f"Supported versions: {list(_IPED_CLASSES.keys())}."
        )
    return cls


class Iped(ConfigBaseClass):
    """IPED factory class that dispatches to IpedV1 or IpedV2 based on family database.

    This class provides the public interface for IPED operations. It delegates to
    the version-specific class determined by the ``iped_version`` database key.
    """

    FEATURE = DatabaseManager.IPED

    @classmethod
    def get_supported_families(cls, include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get all families that support IPED (any version).

        :param include_predecessors: Whether to include predecessor families.
        :return: List of supported family revisions.
        """
        return get_families(feature=cls.FEATURE, include_predecessors=include_predecessors)

    @classmethod
    def get_iped_class(cls, family: FamilyRevision) -> type[IpedV1] | type[IpedV2]:
        """Get the IPED implementation class for the given family.

        :param family: Target family.
        :return: IPED class (IpedV1 or IpedV2).
        """
        return _get_iped_class(family)

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get validation schemas for IPED configuration.

        Dispatches to the correct version's schemas based on family.

        :param family: Target family.
        :return: List of validation schemas.
        """
        iped_cls = _get_iped_class(family)
        return iped_cls.get_validation_schemas(family)

    @classmethod
    def get_validation_schemas_from_cfg(cls, config: Config) -> list[dict[str, Any]]:
        """Get validation schemas based on configuration.

        :param config: Configuration object containing family info.
        :return: List of validation schemas.
        """
        config.check(cls.get_validation_schemas_basic())
        family = FamilyRevision.load_from_config(config)
        return cls.get_validation_schemas(family)

    @classmethod
    def get_validation_schemas_basic(cls) -> list[dict[str, Any]]:
        """Get basic validation schemas for family key.

        :return: List of validation schemas with supported families.
        """
        from spsdk.utils.database import get_schema_file
        from spsdk.utils.family import update_validation_schema_family

        family_schema = get_schema_file("general")["family"]
        update_validation_schema_family(
            sch=family_schema["properties"], devices=cls.get_supported_families()
        )
        return [family_schema]

    @classmethod
    def load_from_config(cls, config: Config) -> IpedV1 | IpedV2:  # type: ignore[override]
        """Load IPED from configuration, dispatching to the correct version.

        :param config: IPED configuration.
        :return: IPED object (IpedV1 or IpedV2).
        """
        family = FamilyRevision.load_from_config(config)
        iped_cls = _get_iped_class(family)
        return iped_cls.load_from_config(config)

    @classmethod
    def parse(cls, data: bytes, family: FamilyRevision) -> IpedV1 | IpedV2:
        """Parse IPED from binary data, dispatching to the correct version.

        :param data: Input binary data.
        :param family: Target family.
        :return: Parsed IPED object (IpedV1 or IpedV2).
        """
        iped_cls = _get_iped_class(family)
        return iped_cls.parse(data, family=family)

    @classmethod
    def get_config_template(cls, family: FamilyRevision) -> str:
        """Get configuration template for the given family.

        :param family: Target family.
        :return: YAML configuration template string.
        """
        iped_cls = _get_iped_class(family)
        return iped_cls.get_config_template(family)

    def get_config(self, data_path: str = "./") -> Config:
        """Get configuration - not used directly on factory class.

        :param data_path: Path to store the data files of configuration.
        :raises SPSDKValueError: Always, as Iped factory is not directly instantiated.
        """
        raise SPSDKValueError("Iped factory class should not be instantiated directly.")
