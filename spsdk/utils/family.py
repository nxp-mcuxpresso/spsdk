#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK device family and revision management utilities.

This module provides functionality for managing device families, revisions,
and database operations across the NXP MCU portfolio. It includes utilities
for family validation, device lookup, and database management operations.
"""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, Device, Features

logger = logging.getLogger(__name__)


class FamilyRevision:
    """SPSDK family and revision identifier.

    This class represents a device family name paired with its revision information,
    providing standardized handling of family names and revision resolution. It manages
    family name validation through the database manager and supports revision aliasing
    where "latest" automatically resolves to the most current revision available.
    """

    def __init__(self, name: str, revision: str = "latest") -> None:
        """Family revision class constructor.

        :param name: Family name (can be abbreviation that will be translated to correct name).
        :param revision: Device revision specification, defaults to "latest".
        """
        self.name = DatabaseManager().quick_info.devices.get_correct_name(name)
        if name != self.name:
            logger.debug(
                f"The abbreviation family name '{name}' "
                f"has been translated to current one: '{self.name}')"
            )

        self.revision = revision

    def __str__(self) -> str:
        """Return string representation of the object.

        :return: Formatted string containing name and revision information.
        """
        return f"{self.name}, Revision: {self.revision}"

    def __repr__(self) -> str:
        """Return string representation of the object.

        :return: String containing name and revision information.
        """
        return f"{self.name}, Revision: {self.revision}"

    def get_real_revision(self) -> str:
        """Get the real revision name.

        Translates 'latest' revision identifier to the actual latest revision name
        for the device family, or returns the original revision if not 'latest'.

        :return: Real revision name string.
        """
        if self.revision != "latest":
            return self.revision

        return DatabaseManager().quick_info.devices.devices[self.name].latest_rev

    def __eq__(self, other: object) -> bool:
        """Check equality between two FamilyRevision objects.

        Compares both the family name and the real revision number to determine
        if two FamilyRevision instances represent the same family and revision.

        :param other: Object to compare with this FamilyRevision instance.
        :return: True if both objects are FamilyRevision instances with matching
                 name and real revision, False otherwise.
        """
        if isinstance(other, FamilyRevision):
            return self.name == other.name and self.get_real_revision() == other.get_real_revision()
        return False

    def __hash__(self) -> int:
        """Generate hash value for the object.

        Returns hash based on the object's name and revision attributes to enable
        proper usage in hash-based collections like sets and dictionaries.

        :return: Hash value computed from name and revision.
        """
        return hash((self.name, self.revision))

    def __lt__(self, other: "FamilyRevision") -> bool:
        """Compare this family revision with another for ordering.

        Implements the less-than comparison operator for FamilyRevision objects based on their name
        attribute for sorting and ordering operations.

        :param other: Another FamilyRevision instance to compare against.
        :return: True if this revision's name is lexicographically less than the other's name,
                 NotImplemented if the other object is not a FamilyRevision instance.
        """
        if isinstance(other, FamilyRevision):
            return self.name < other.name
        return NotImplemented

    def casefold(self) -> "FamilyRevision":
        """Create a case-folded copy of the FamilyRevision instance.

        Returns a new FamilyRevision object with both device name and revision converted to
        lowercase using Unicode case folding rules for case-insensitive comparisons.

        :return: New FamilyRevision instance with case-folded names.
        """
        return FamilyRevision(self.name.casefold(), self.revision.casefold())

    @classmethod
    def load_from_config(cls, config: dict) -> Self:
        """Load FamilyRevision from a configuration dictionary.

        Creates a new FamilyRevision instance using family and revision information from the provided
        configuration dictionary. The revision defaults to 'latest' if not specified.

        :param config: Configuration dictionary containing 'family' key (required) and optional
                       'revision' key.
        :raises SPSDKError: When config is not a dictionary or family is not specified.
        :return: FamilyRevision instance with normalized family and revision names.
        """
        if not isinstance(config, dict):
            raise SPSDKError("Configuration, where should be family information, is not dictionary")
        family: Optional[str] = config.get("family")
        if not family:
            raise SPSDKError("Family must be specified in configuration")
        revision: str = config.get("revision", "latest")
        return cls(family.lower(), revision.lower())


def update_validation_schema_family(
    sch: dict[str, Any], devices: list[FamilyRevision], family: Optional[FamilyRevision] = None
) -> None:
    """Update validation family schema to properly validate and show the families.

    The method modifies the schema dictionary in-place to set up proper enumeration values for
    family and revision fields. It handles device name deduplication, predecessor device lookup,
    and conditional revision schema updates based on the provided family parameter.

    :param sch: The validation schema dictionary containing 'properties' with family and revision
        fields
    :param devices: List of supported device family revisions
    :param family: Optional family revision, if provided the template value will be updated and
        the correct list of revisions will be used for validation
    """
    family_sch = sch["family"]
    # remove duplicate device names as the list may contain devices with multiple revisions
    device_names = list(set([x.name for x in devices]))
    family_sch["enum"] = device_names + list(
        DatabaseManager().quick_info.devices.get_predecessors(device_names).keys()
    )

    family_sch["enum_template"] = device_names
    if family:
        family_sch["enum_template"] = []  # In purposes to reduce showed huge list of families
        family_sch["template_value"] = family.name
        if "revision" in sch:
            revision_sch = sch["revision"]
            device = get_db(family).device
            revision_sch["enum"] = device.revisions.revision_names(append_latest=True)
            revision_sch["template_value"] = family.revision
    if len(device_names) == 0:
        family_sch.pop("enum")
        family_sch.pop("enum_template")


def get_db(family: FamilyRevision) -> Features:
    """Get family feature database for specified family revision.

    :param family: The family revision object to get features for.
    :return: Features object containing all feature data for the family.
    """
    return DatabaseManager().db.get_device_features(family.name, family.revision)


def get_device(family: FamilyRevision) -> Device:
    """Get device database object for specified family.

    :param family: The family revision object to get device data for.
    :return: Device object containing all device data.
    """
    return DatabaseManager().db.devices.get(family.name)


def get_families(
    feature: Optional[str] = None,
    sub_feature: Optional[str] = None,
    include_predecessors: bool = False,
    single_revision: bool = False,
) -> list[FamilyRevision]:
    """Get the list of all families that supports requested feature.

    The method retrieves family information from the database manager and filters based on
    specified criteria. It can include predecessor families and optionally return only the
    latest revision per family.

    :param feature: Name of feature, if omitted all supported devices will be returned.
    :param sub_feature: Optional sub feature name to specify more precise selection.
    :param include_predecessors: The list will contain also predecessor family names.
    :param single_revision: If True, return only one revision per family (latest applicable).
    :return: List of FamilyRevision objects matching the specified criteria.
    """
    families: dict[str, list[str]] = {}
    if feature:
        families = DatabaseManager().quick_info.devices.get_devices_with_feature(
            feature, sub_feature
        )
    else:
        names = DatabaseManager().quick_info.devices.get_family_names()
        families = {
            name: DatabaseManager().quick_info.devices.devices[name].revisions for name in names
        }
    if include_predecessors:
        predecessors = DatabaseManager().quick_info.devices.get_predecessors(list(families.keys()))
        for predecessor, name in predecessors.items():
            families[predecessor] = DatabaseManager().quick_info.devices.devices[name].revisions
    # create final FamilyRevision objects
    result = []
    for family_name, revisions in families.items():
        if single_revision:
            # Get the latest applicable revision
            revision = revisions[-1]
            latest = DatabaseManager().quick_info.devices.devices[family_name].latest_rev
            if latest in revisions:
                revision = latest
            result.append(
                FamilyRevision(family_name, revision)
            )  # Will use 'latest' as default revision
        else:
            for revision in revisions:
                result.append(FamilyRevision(family_name, revision))
    return result


def split_by_family_name(families: list[FamilyRevision]) -> dict[str, list[str]]:
    """Split list of families by family name.

    Groups family revisions by their family name, creating a dictionary where each key
    is a family name and the value is a list of all revisions for that family.

    :param families: List of FamilyRevision objects to be grouped by family name.
    :return: Dictionary mapping family names to lists of their revisions.
    """
    families_dict: dict[str, list] = {}
    for family in families:
        if family.name not in families_dict:
            families_dict[family.name] = []
        families_dict[family.name].append(family.revision)
    return families_dict
