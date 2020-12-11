#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Translator is responsible for converting stringified keys into values."""

import logging

import jmespath
from .pfr import CFPA, CMPA


class Translator:
    """Translates single strings (register/key names) into values."""

    def __init__(self, cmpa_data: dict, cfpa_data: dict) -> None:
        """Initialize CMPA and CFPA data.

        :param cmpa_data: data loaded from CMPA json config file
        :param cfpa_data: data loaded from CFPA json config file
        """
        self.logger = logging.getLogger("translator")
        self.cmpa_data = cmpa_data
        self.cmpa_obj = CMPA(
            device=cmpa_data['device'], revision=cmpa_data['revision'],
            user_config=cmpa_data['settings']
        )
        self.cfpa_data = cfpa_data
        self.cfpa_obj = CFPA(
            device=cfpa_data['device'], revision=cfpa_data['revision'],
            user_config=cfpa_data['settings']
        )
        self.handlers = {
            'CMPA': self._cmpa_translate,
            'CFPA': self._cfpa_translate,
            'UTIL': self._util_translate
        }

    def translate(self, key: str) -> int:
        """Lookup register's (or generic key's) value.

        :param key: Register's (key's) stringified name
        :return: Register's (key's) value
        """
        area, value = key.split('.', maxsplit=1)
        self.logger.debug(f"Area designator: {area}")
        self.logger.debug(f"Register designator: {value}")
        return self.handlers[area](value)

    def _cmpa_translate(self, key: str) -> int:
        """Handler for CMPA data."""
        self.logger.debug(f'Extracting value from {key}')
        value = jmespath.search(key, self.cmpa_data['settings'])
        if isinstance(value, dict):
            reg_bytes = self.cmpa_obj._export_register(register_name=key, compute_inverses=False)
            reg_val = int.from_bytes(bytes=reg_bytes, byteorder="little")
            value = reg_val
        else:
            value = int(value, 0)
        self.logger.debug(f"Extracted value {value:x}")

        return value

    def _cfpa_translate(self, key: str) -> int:
        """Handler for CFPA data."""
        self.logger.debug(f'Extracting value from {key}')

        value = jmespath.search(key, self.cfpa_data['settings'])
        if isinstance(value, dict):
            reg_bytes = self.cfpa_obj._export_register(register_name=key, compute_inverses=False)
            reg_val = int.from_bytes(bytes=reg_bytes, byteorder="little")
            value = reg_val
        else:
            value = int(value, 0)
        self.logger.debug("Extracted value {value:x}")

        return value

    def _util_translate(self, key: str) -> int:
        """Handler for Utils data."""
        values = {
            'has_USD': False
        }
        return values[key]
