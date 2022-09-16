#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers configuration."""

import os
from typing import Any, Dict, List, Optional

from spsdk import SPSDKError
from spsdk.utils.database import Database
from spsdk.utils.misc import value_to_int


class RegConfig(Database):
    """Class that helps manage the registers configuration."""

    def get_address(self, device: str) -> int:
        """Get the area address in chip memory.

        :param device: The device name.
        :return: Base address of registers.
        """
        return value_to_int(self.config["devices"][device]["address"])

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

    def get_computed_registers(self, device: str = None) -> Dict[str, Any]:
        """Return the dictionary of computed registers.

        :param device: The device name, if not specified, the general value is used.
        :return: The dictionary of computed registers.
        """
        val = self.get_value("computed_registers", device, default={})
        assert isinstance(val, dict)
        return val

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
        return self.get_device_value(key=key, device=device, default=default)
