#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers configuration."""

import os
from typing import Any, Dict, List, Optional

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.database import Database
from spsdk.utils.misc import value_to_int


class RegConfig(Database):
    """Class that helps manage the registers configuration."""

    def get_address(self, device: str, alt_read_address: bool = False) -> int:
        """Get the area address in chip memory.

        :param device: The device name.
        :param alt_read_address: The flag is used if an alternate read address applies.
        :return: Base address of registers.
        """
        address = self.devices.get_by_name(device).attributes["address"]
        if alt_read_address:
            address = self.devices.get_by_name(device).attributes.get("read_address", address)
        return value_to_int(address)

    def get_data_file(self, device: str, revision: str) -> str:
        """Return the full path to data file (xml).

        :param device: The device name.
        :param revision: The chip revision.
        :raises SPSDKValueError: When datafile is not defined in the database
        :return: The path to data file.
        """
        file_name = self.devices.get_by_name(device).revisions.get(revision).data_file
        if not file_name:
            raise SPSDKValueError(
                f"Datafile is not defined in database: {self.path} for device {device} and revision {revision}"
            )
        dir_path = os.path.dirname(os.path.abspath(self.path))
        return os.path.join(dir_path, file_name)

    def get_antipole_regs(self, device: Optional[str] = None) -> Dict[str, str]:
        """Return the list of inverted registers.

        :param device: The device name.
        :return: The dictionary of antipole registers.
        """
        val = self.get_value("inverted_regs", device, default={})
        assert isinstance(val, dict)
        return dict(val)

    def get_computed_fields(self, device: Optional[str] = None) -> Dict[str, Dict[str, str]]:
        """Return the list of computed fields (not used in config YML files).

        :param device: The device name, if not specified, the general value is used.
        :return: The dictionary of computed fields.
        """
        val = self.get_value("computed_fields", device, default={})
        assert isinstance(val, dict)
        return dict(val)

    def get_computed_registers(self, device: Optional[str] = None) -> Dict[str, Any]:
        """Return the dictionary of computed registers.

        :param device: The device name, if not specified, the general value is used.
        :return: The dictionary of computed registers.
        """
        val = self.get_value("computed_registers", device, default={})
        assert isinstance(val, dict)
        return val

    def get_grouped_registers(self, device: Optional[str] = None) -> List[dict]:
        """Return the list of grouped registers description.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of grouped registers descriptions.
        """
        val = self.get_value("grouped_registers", device, default=[])
        assert isinstance(val, list)
        return list(val)

    def get_ignored_fields(self, device: Optional[str] = None) -> List[str]:
        """Return the list of ignored fields.

        :param device: The device name, if not specified, the general value is used.
        :return: The list of ignored fields.
        """
        val = self.get_value("ignored_fields", device, default=[])
        assert isinstance(val, list)
        return val

    def get_seal_start_address(self, device: Optional[str] = None) -> Optional[str]:
        """Return the seal start address.

        :param device: The device name, if not specified, the general value is used.
        :return: The seal start register name.
        :raises SPSDKError: When seal start address has invalid name
        """
        val = self.get_value("seal_start", device)
        if not (val is None or isinstance(val, str)):
            raise SPSDKError("Invalid seal start address name")
        return val

    def get_seal_count(self, device: Optional[str] = None) -> Optional[int]:
        """Return the seal count.

        :param device: The device name, if not specified, the general value is used.
        :return: The seal count.
        :raises SPSDKError: When there is invalid seal count
        """
        val = self.get_value("seal_count", device)
        if not (val is None or isinstance(val, int)):
            raise SPSDKError("Invalid seal count")
        return val

    def get_value(
        self, key: str, device: Optional[str] = None, default: Optional[Any] = None
    ) -> Any:
        """Return any parameter by key.

        :param key: The Key of the parameter to be returned.
        :param device: The device name.
        :param default: The default Value in case that is not specified in config file.
        :return: The Value of parameter by handled Key.
        """
        return self.get_device_value(key=key, device=device, default=default)
