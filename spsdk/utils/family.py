#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Miscellaneous functions used throughout the SPSDK."""

import logging
from typing import Any, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.database import DatabaseManager, Device, Features

logger = logging.getLogger(__name__)


class FamilyRevision:
    """Class keeping family name and revision information."""

    def __init__(self, name: str, revision: str = "latest") -> None:
        """Family revision class constructor.

        :param family: Mandatory family
        :param revision: Optionally revision, defaults to "latest"
        """
        self.name = DatabaseManager().quick_info.devices.get_correct_name(name)
        if name != self.name:
            logger.debug(
                f"The abbreviation family name '{name}' "
                f"has been translated to current one: '{self.name}')"
            )

        self.revision = revision

    def __str__(self) -> str:
        return f"{self.name}, Revision: {self.revision}"

    def __repr__(self) -> str:
        return f"{self.name}, Revision: {self.revision}"

    def get_real_revision(self) -> str:
        """Returns real name of revision (translate possible latest to real name)."""
        if self.revision != "latest":
            return self.revision

        return DatabaseManager().quick_info.devices.devices[self.name].latest_rev

    def __eq__(self, other: object) -> bool:
        if isinstance(other, FamilyRevision):
            return self.name == other.name and self.get_real_revision() == other.get_real_revision()
        return False

    def __hash__(self) -> int:
        return hash((self.name, self.revision))

    def __lt__(self, other: "FamilyRevision") -> bool:
        if isinstance(other, FamilyRevision):
            return self.name < other.name
        return NotImplemented

    def casefold(self) -> "FamilyRevision":
        """Case Fold of device and revision names."""
        return FamilyRevision(self.name.casefold(), self.revision.casefold())

    @classmethod
    def load_from_config(cls, config: dict) -> Self:
        """Load FamilyRevision from a configuration dictionary.

        :param config: Configuration dictionary with 'family' and 'revision' keys.
        :return: FamilyRevision instance.
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

    :param sch: The validation schema dictionary containing 'properties' with family and revision fields
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

    :param feature: Name of feature, if omitted all supported devices will be return.
    :param sub_feature: Optional sub feature name to specify the more precise selection.
    :param include_predecessors: The list will contains also predecessors names
    :param single_revision: If True, return only one revision per family (latest applicable)
    :return: List of devices.
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
    """Split list of families by family name."""
    families_dict: dict[str, list] = {}
    for family in families:
        if family.name not in families_dict:
            families_dict[family.name] = []
        families_dict[family.name].append(family.revision)
    return families_dict
