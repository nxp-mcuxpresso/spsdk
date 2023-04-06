#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to manage used databases in SPSDK."""


import dataclasses
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKError, SPSDKTypeError, SPSDKValueError
from spsdk.utils.misc import find_first, load_configuration


@dataclass
class Revision:
    """Revision dataclass represents a single device revision."""

    name: str
    is_latest: bool
    data_file: Optional[str] = None
    attributes: dict = dataclasses.field(default_factory=dict)

    @staticmethod
    def load(name: str, revision: dict, is_latest: bool = False) -> "Revision":
        """Loads the revision from dictionary.

        :param name: The revision name.
        :param revision: Revision data.
        :param is_latest: Is latest device revision.
        :raises SPSDKTypeError: In case the revision is not a dictionary type
        :return: The Revision object.
        """
        if not isinstance(revision, dict):
            raise SPSDKTypeError(f"Revision {name} must be a dict type.")
        rev = Revision(name=name, is_latest=is_latest)
        rev.data_file = revision.get("data_file")
        rev.attributes = revision.get("attributes", {})
        return rev


class Revisions(List[Revision]):
    """List of device revisions."""

    @property
    def revision_names(self) -> List[str]:
        """Get list of revisions.

        :return: List of all supported device version.
        """
        return [rev.name for rev in self]

    def get(self, name: Optional[str] = None) -> Revision:
        """Get the revision by its name.

        If name is not specified, or equal to 'latest', then the latest revision is returned.

        :param name: The revision name.
        :return: The Revision object.
        """
        if name is None or name == "latest":
            return self.get_latest()
        return self.get_by_name(name)

    def get_by_name(self, name: str) -> Revision:
        """Get the required revision.

        :param name: Required revision name
        :raises SPSDKValueError: Incase of invalid device or revision value.
        :return: The Revision object.
        """
        revision = find_first(self, lambda rev: rev.name == name)
        if not revision:
            raise SPSDKValueError(f"Requested revision {revision} is not supported.")
        return revision

    def get_latest(self) -> Revision:
        """Get latest revision for device.

        :raises SPSDKValueError: Incase of there is no latest revision defined.
        :return: The Revision object.
        """
        revision = find_first(self, lambda rev: rev.is_latest)
        if not revision:
            raise SPSDKValueError("No latest revision has been defined.")
        return revision

    @staticmethod
    def load(revisions: dict, latest: Optional[str] = None) -> "Revisions":
        """Loads the revisions list from dictionary.

        :param revisions: Revisions data.
        :param latest: Name of latest revision.
        :raises SPSDKTypeError: In case the revisions parameter is not a dictionary type
        :return: The Revisions object.
        """
        if not isinstance(revisions, dict):
            raise SPSDKTypeError(f"Revisions must be a dictionary type, not {type(revisions)}.")
        return Revisions(
            Revision.load(name, val, is_latest=name == latest) for name, val in revisions.items()
        )


@dataclass
class Device:
    """Device dataclass represents a single device."""

    name: str
    device_alias: Optional[str] = None
    revisions: Revisions = dataclasses.field(default_factory=Revisions)
    attributes: dict = dataclasses.field(default_factory=dict)

    @staticmethod
    def load(name: str, device: dict) -> "Device":
        """Loads the device from dictionary.

        :param name: The name of device.
        :param device: Device data.
        :return: The Device object.
        """
        dev = Device(name=name)
        if "device_alias" in device:
            dev.device_alias = device["device_alias"]
        dev.revisions = Revisions.load(
            device.get("revisions", {}), latest=device.get("latest", None)
        )
        dev.attributes = device.get("attributes", {})
        return dev


class Devices(List[Device]):
    """List of devices."""

    @property
    def device_names(self) -> List[str]:
        """Get the list of all device names."""
        devices = [dev.name for dev in self]
        devices.sort()
        return devices

    def get_by_name(self, name: str) -> Device:
        """Return database device structure.

        :param name: String Key with device name.
        :raises SPSDKValueError: In case the device with given name does not exist
        :return: Dictionary device configuration structure or None:
        """
        dev = find_first(self, lambda dev: dev.name == name)
        if not dev:
            raise SPSDKValueError(f"The device with name {name} is not in the database.")
        if dev.device_alias:
            return self.get_by_name(dev.device_alias)
        return dev

    @staticmethod
    def load(devices: dict) -> "Devices":
        """Loads the device from dictionary.

        :param devices: Devices data.
        :return: The Devices object.
        """
        return Devices(Device.load(name, val) for name, val in devices.items())

    @staticmethod
    def load_from_file(path: str) -> "Devices":
        """Loads the device from database file.

        :param path: path to database file.
        :return: The Devices object.
        """
        config: Dict[str, Any] = load_configuration(path)
        return Devices.load(config["devices"])


class Database:
    """Class that helps manage used databases in SPSDK."""

    def __init__(self, path: str, index: Optional[int] = None) -> None:
        """Register Configuration class constructor.

        :param path: The path to configuration JSON file.
        :param index: Values with {index} will be replaced with index value
        """
        self.path = path
        self.index = index
        config: Dict[str, Any] = load_configuration(path)
        try:
            self._devices = Devices.load(config["devices"])
        except (SPSDKValueError, SPSDKTypeError) as exc:
            if exc.description:
                exc.description += f"File path: {self.path}"
            raise SPSDKError("Database can not be created")
        self.attributes: dict = config.get("attributes", {})

    @classmethod
    def get_devices(cls, path: str) -> Devices:
        """Classmethod to get list of supported devices.

        :param path: Path to database file.
        :return: List of all supported devices.
        """
        return Devices.load_from_file(path)

    @property
    def devices(self) -> Devices:
        """Get the list of devices stored in the database."""
        return self._devices

    def replace_idx_value(self, value: str) -> str:
        """Replace index value if provided in the database.

        :param value: value to be replaced f-string containing index
        :return: value with replaced index
        """
        if self.index and isinstance(value, str):
            value = value.replace("{index}", str(self.index))
        if self.index and isinstance(value, list):
            for reg in value:
                reg["name"] = reg["name"].replace("{index}", str(self.index))
        return value

    def get_device_value(
        self,
        key: str,
        device: Optional[str] = None,
        revision: str = "latest",
        default: Optional[Any] = None,
    ) -> Any:
        """Return any parameter by key and replace the index if provided in DB.

        :param key: The Key of the parameter to be returned.
        :param device: The device name.
        :param revision: The revision of the silicon.
        :param default: The default Value in case that is not specified in config file.
        :return: The Value of parameter by handled Key.
        """
        if device and device in self.devices.device_names:
            dev = self.devices.get_by_name(device)
            try:
                rev = dev.revisions.get(revision)
            except SPSDKValueError:
                rev = None
            if rev and key in rev.attributes:
                return self.replace_idx_value(rev.attributes[key])
            if key in dev.attributes:
                return self.replace_idx_value(dev.attributes[key])

        return self.replace_idx_value(self.attributes.get(key, default))
