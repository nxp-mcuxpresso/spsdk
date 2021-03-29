#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers configuration."""

import os
import logging
from typing import List, Dict
import json

logger = logging.getLogger(__name__)

class RegConfig():
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
        return list(config['devices'].keys())

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
        dev = self._get_device(device)
        if dev and "inverted_regs" in dev.keys():
            # Get device specific
            inverted_regs = dev.get("inverted_regs", {})
        else:
            # get the general one
            inverted_regs = self.config.get("inverted_regs", {})
        return dict(inverted_regs)

    def get_computed_fields(self, device: str = None) -> Dict[str, Dict[str, str]]:
        """Return the list of computed fields (not used in config YML files).

        :param device: The device name, if not specified, the general value is used.
        :return: The dictionary of computed fields.
        """
        dev = self._get_device(device)
        if dev and "computed_fields" in dev.keys():
            # Get device specific
            computed_fields = dev.get("computed_fields", {})
        else:
            # get the general one
            computed_fields = self.config.get("computed_fields", {})
        return dict(computed_fields)

    def get_computed_registers(self, device: str = None) -> List[str]:
        """Return the list of computed registers.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of computed registers.
        """
        dev = self._get_device(device)
        if dev and "computed_registers" in dev.keys():
            # Get device specific
            computed_registers = dev.get("computed_registers", [])
        else:
            # get the general one
            computed_registers = self.config.get("computed_registers", [])
        return list(computed_registers)

    def get_grouped_registers(self, device: str = None) -> List[dict]:
        """Return the list of grouped registers description.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of grouped registers descriptions.
        """
        dev = self._get_device(device)
        if dev and "grouped_registers" in dev.keys():
            # Get device specific
            grouped_registers = dev.get("grouped_registers", [])
        else:
            # get the general one
            grouped_registers = self.config.get("grouped_registers", [])
        return list(grouped_registers)

    def get_ignored_registers(self, device: str = None) -> List[str]:
        """Return the list of ignored registers.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of ignored register.
        """
        dev = self._get_device(device)
        if dev and "ignored_registers" in dev.keys():
            # Get device specific
            ignored_registers = dev.get("ignored_registers", [])
        else:
            # get the general one
            ignored_registers = self.config.get("ignored_registers", [])
        return list(ignored_registers)

    def get_ignored_fields(self, device: str = None) -> List[str]:
        """Return the list of ignored fields.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of ignored fields.
        """
        dev = self._get_device(device)
        if dev and "ignored_fields" in dev.keys():
            # Get device specific
            ignored_fields = dev.get("ignored_fields", [])
        else:
            # get the general one
            ignored_fields = self.config.get("ignored_fields", [])
        return list(ignored_fields)

    def get_seal_start_address(self, device: str = None) -> str:
        """Return the seal start address.

        :param device: The device name, if not specified, the general value is used.
        :return: The seal start register name.
        """
        dev = self._get_device(device)
        if dev and "seal_start" in dev.keys():
            # Get device specific
            seal_start = dev.get("seal_start", None)
        else:
            # get the general one
            seal_start = self.config.get("seal_start", None)
        return seal_start

    def get_seal_count(self, device: str = None) -> str:
        """Return the seal count.

        :param device: The device name, if not specified, the general value is used.
        :return: The seal count.
        """
        dev = self._get_device(device)
        if dev and "seal_count" in dev.keys():
            # Get device specific
            seal_count = dev.get("seal_count", None)
        else:
            # get the general one
            seal_count = self.config.get("seal_count", None)
        return seal_count
