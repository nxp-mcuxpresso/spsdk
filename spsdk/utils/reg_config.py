#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module to handle registers configuration."""

from typing import Any, Dict, List, Optional, Union

from spsdk.utils.database import get_db


class RegConfig:
    """Class that helps manage the registers configuration."""

    def __init__(
        self,
        family: str,
        feature: str,
        revision: str = "latest",
        db_path: Optional[List[str]] = None,
    ) -> None:
        """Initialize the class that handles information regarding register settings.

        :param family: Family name
        :param feature: Feature name
        :param revision: Revision of family
        :param db_path: Optional database path list of nested information
        """
        self.family = family
        self.feature = feature
        self.db = get_db(device=family, revision=revision)
        self.revision = self.db.name
        self.db_path = db_path

    def _get_path(self, key: str) -> Union[str, List[str]]:
        """Get the key path in revision.

        :param key: The requested key.
        :return: Key or key path to item.
        """
        if self.db_path:
            return self.db_path + [key]

        return key

    def get_address(self, alt_read_address: bool = False) -> int:
        """Get the area address in chip memory.

        :param alt_read_address: The flag is used if an alternate read address applies.
        :return: Base address of registers.
        """
        address = self.db.get_int(self.feature, self._get_path("address"))
        if alt_read_address:
            return self.db.get_int(self.feature, self._get_path("read_address"), address)
        return address

    def get_data_file(self) -> str:
        """Return the full path to data file (xml).

        :raises SPSDKValueError: When datafile is not defined in the database
        :return: The path to data file.
        """
        return self.db.get_file_path(self.feature, self._get_path("data_file"))

    def get_antipole_regs(self) -> Dict[str, str]:
        """Return the list of inverted registers.

        :return: The dictionary of antipole registers.
        """
        return self.db.get_dict(self.feature, self._get_path("inverted_regs"), {})

    def get_computed_fields(self) -> Dict[str, Dict[str, str]]:
        """Return the list of computed fields (not used in config YML files).

        :return: The dictionary of computed fields.
        """
        return self.db.get_dict(self.feature, self._get_path("computed_fields"), {})

    def get_computed_registers(self) -> Dict[str, Any]:
        """Return the dictionary of computed registers.

        :return: The dictionary of computed registers.
        """
        return self.db.get_dict(self.feature, self._get_path("computed_registers"), {})

    def get_grouped_registers(self) -> List[dict]:
        """Return the list of grouped registers description.

        :return: The list of grouped registers descriptions.
        """
        return self.db.get_list(self.feature, self._get_path("grouped_registers"), [])

    def get_seal_start_address(self) -> Optional[str]:
        """Return the seal start address.

        :return: The seal start register name.
        :raises SPSDKError: When seal start address has invalid name
        """
        return self.db.get_str(self.feature, self._get_path("seal_start"))

    def get_seal_count(self) -> Optional[int]:
        """Return the seal count.

        :return: The seal count.
        :raises SPSDKError: When there is invalid seal count
        """
        return self.db.get_int(self.feature, self._get_path("seal_count"))

    def get_value(self, key: str, default: Optional[Any] = None) -> Any:
        """Return any parameter by key.

        :param key: The Key of the parameter to be returned.
        :param default: The default Value in case that is not specified in config file.
        :return: The Value of parameter by handled Key.
        """
        return self.db.get_value(self.feature, self._get_path(key), default)
