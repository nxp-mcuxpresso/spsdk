#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to manage used databases in SPSDK."""


from typing import Any, Dict, List

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.misc import load_configuration


class Database:
    """Class that helps manage used databases in SPSDK."""

    def __init__(self, path: str) -> None:
        """Register Configuration class constructor.

        :param path: The path to configuration JSON file.
        """
        self.path = path
        self.config: Dict[str, Any] = load_configuration(path)

    @classmethod
    def devices(cls, path: str) -> List[str]:
        """Classmethod to get list of supported devices.

        :param path: Path to database file.
        :return: List of all supported devices.
        """
        config = load_configuration(path)
        return list(config["devices"].keys())

    def get_devices(self) -> List[str]:
        """Get list of supported devices.

        :return: List of supported device.
        """
        return list(self.config["devices"].keys())

    def _get_device(self, device: str = None) -> dict:
        """Return database device structure.

        :param device: String Key with device name.
        :return: Dictionary device configuration structure or None:
        """
        dev = self.config["devices"].get(device, None)
        if dev and "device_alias" in dev.keys():
            return self._get_device(dev["device_alias"])
        return dev

    def get_latest_revision(self, device: str) -> str:
        """Get latest revision for device.

        :param device: The device name.
        :return: The name of latest revision.
        """
        return self.config["devices"][device]["latest"]

    def get_revisions(self, device: str) -> List[str]:
        """Get list of revisions for given device.

        :param device: The device name.
        :return: List of all supported device version.
        """
        try:
            return list(self.config["devices"][device]["revisions"].keys())
        except KeyError:
            return []

    def get_revision(self, device: str, rev: str = "latest") -> str:
        """Get the required revision.

        :param device: Name of device.
        :param rev: Required revision name, defaults to "latest"
        :raises SPSDKValueError: Incase of invalid device or revision value.
        :return: Name of real silicon revision.
        """
        dev = self._get_device(device)
        if not dev:
            raise SPSDKValueError(f"The {device} is not in {self.path} database.")

        if rev == "latest":
            if "latest" not in dev.keys():
                raise SPSDKValueError(
                    f"The latest revision is not supported by {device} in {self.path} database."
                )
            return dev["latest"]

        revisions = self.get_revisions(device)
        if revisions and rev not in revisions:
            raise SPSDKValueError(
                f"Requested revision [{rev}] is not supported by {device} in {self.path} database."
            )

        return rev

    def get_device_value(
        self, key: str, device: str = None, revision: str = "latest", default: Any = None
    ) -> Any:
        """Return any parameter by key.

        :param key: The Key of the parameter to be returned.
        :param device: The device name.
        :param revision: The revision of the silicon.
        :param default: The default Value in case that is not specified in config file.
        :return: The Value of parameter by handled Key.
        """
        dev = self._get_device(device)
        # Try to get device specific
        if device and dev and key in dev.keys():
            try:
                rev = self.get_revision(device, revision)
                if (
                    "revisions" in dev.keys()
                    and rev in dev["revisions"].keys()
                    and isinstance(dev["revisions"][rev], dict)
                    and key in dev["revisions"][rev].keys()
                ):
                    return dev["revisions"][rev][key]
            except SPSDKValueError:
                pass
            if dev and key in dev.keys():
                return dev[key]
        # get the general one if available, default otherwise
        return self.config.get(key, default)
