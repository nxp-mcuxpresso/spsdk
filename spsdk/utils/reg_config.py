#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers configuration."""

import json
import logging
import os
from typing import Any, Dict, List, Optional

from spsdk import SPSDKError

logger = logging.getLogger(__name__)


class RegConfig:
    """Class that helps manage the registers configuration."""

    def __init__(self, path: str) -> None:
        """Register Configuration class constructor.

        :param path: The path to configuration JSON file.
        """
        self.path = path
        self.config = RegConfig.load_config(path)

    @classmethod
    def load_config(cls, path: str) -> dict:
        """Load config file.

        :param path: The path to database file.
        :return: The database.
        """
        with open(path) as config_file:
            return json.load(config_file)

    @classmethod
    def devices(cls, path: str) -> List[str]:
        """Classmethod to get list of suppported devices.

        :param path: Path to database file.
        :return: List of all supported devices.
        """
        config = cls.load_config(path)
        return list(config["devices"].keys())

    def _get_device(self, device: str = None) -> dict:
        """Return JSON device structure.

        :param device: String Key with device name.
        :return: Dictionary device configuration structure or None:
        """
        return self.config["devices"].get(device, None)

    def get_latest_revision(self, device: str) -> str:
        """Get latest revision for device.

        :param device: The device name.
        :return: The name of latest revision.
        """
        return self.config["devices"][device]["latest"]

    def get_devices(self) -> List[str]:
        """Get list of supported devices.

        :return: List of supported device.
        """
        return list(self.config["devices"].keys())

    def get_revisions(self, device: str) -> List[str]:
        """Get list of revisions for given device.

        :param device: The device name.
        :return: List of all supported device version.
        """
        return list(self.config["devices"][device]["revisions"].keys())

    def get_address(self, device: str, remove_underscore: bool = False) -> str:
        """Get the area address in chip memory.

        :param device: The device name.
        :param remove_underscore: Remove underscore from address if set.
        :return: Base address of registers.
        """
        address = self.config["devices"][device]["address"]
        if remove_underscore:
            return address.replace("_", "")
        return address

    def get_data_file(self, device: str, revision: str) -> str:
        """Return the full path to data file (xml).

        :param device: The device name.
        :param revision: The chip revision.
        :return: The path to data file.
        """
        file_name = self.config["devices"][device]["revisions"][revision]
        dir_path = os.path.dirname(os.path.abspath(self.path))
        return os.path.join(dir_path, file_name)

    def get_antipole_regs(self, device: str = None) -> Dict[str, str]:
        """Return the list of inverted registers.

        :param device: The device name.
        :return: The dictionary of antipole registers.
        """
        val = self.get_value("inverted_regs", device, default={})
        assert isinstance(val, dict)
        return dict(val)

    def get_computed_fields(self, device: str = None) -> Dict[str, Dict[str, str]]:
        """Return the list of computed fields (not used in config YML files).

        :param device: The device name, if not specified, the general value is used.
        :return: The dictionary of computed fields.
        """
        val = self.get_value("computed_fields", device, default={})
        assert isinstance(val, dict)
        return dict(val)

    def get_computed_registers(self, device: str = None) -> List[str]:
        """Return the list of computed registers.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of computed registers.
        """
        val = self.get_value("computed_registers", device, default=[])
        assert isinstance(val, list)
        return list(val)

    def get_grouped_registers(self, device: str = None) -> List[dict]:
        """Return the list of grouped registers description.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of grouped registers descriptions.
        """
        val = self.get_value("grouped_registers", device, default=[])
        assert isinstance(val, list)
        return list(val)

    def get_ignored_registers(self, device: str = None) -> List[str]:
        """Return the list of ignored registers.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of ignored register.
        """
        val = self.get_value("ignored_registers", device, default=[])
        assert isinstance(val, list)
        return list(val)

    def get_ignored_fields(self, device: str = None) -> List[str]:
        """Return the list of ignored fields.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of ignored fields.
        """
        val = self.get_value("ignored_fields", device, default=[])
        assert isinstance(val, list)
        return val

    def get_seal_start_address(self, device: str = None) -> Optional[str]:
        """Return the seal start address.

        :param device: The device name, if not specified, the general value is used.
        :return: The seal start register name.
        :raises SPSDKError: When seal start address has invalid name
        """
        val = self.get_value("seal_start", device)
        if not (val is None or isinstance(val, str)):
            raise SPSDKError("Invalid seal start address name")
        return val

    def get_seal_count(self, device: str = None) -> Optional[int]:
        """Return the seal count.

        :param device: The device name, if not specified, the general value is used.
        :return: The seal count.
        :raises SPSDKError: When there is invalid seal count
        """
        val = self.get_value("seal_count", device)
        if not (val is None or isinstance(val, int)):
            raise SPSDKError("Invalid seal count")
        return val

    def get_value(self, key: str, device: str = None, default: Any = None) -> Any:
        """Return any parameter by key.

        :param key: The Key of the parameter to be returned.
        :param device: The device name.
        :param default: The default Value in case that is not specified in config file.
        :return: The Value of parameter by handled Key.
        """
        dev = self._get_device(device)
        # Try to get device specific
        if dev and key in dev.keys():
            return dev[key]
        # get the general one if available, default otherwise
        return self.config.get(key, default)
