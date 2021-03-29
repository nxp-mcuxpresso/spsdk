#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Translator is responsible for converting stringified keys into values."""

import logging
from .pfr import CFPA, CMPA, PfrConfiguration


class Translator:
    """Translates single strings (register/key names) into values."""

    def __init__(self, cmpa: PfrConfiguration, cfpa: PfrConfiguration) -> None:
        """Initialize CMPA and CFPA data.

        :param cmpa: configuration data loaded from CMPA config file
        :param cfpa: configuration data loaded from CFPA config file
        """
        self.logger = logging.getLogger("translator")
        self.cmpa_cfg = cmpa
        self.cmpa_obj = CMPA(
            device=cmpa.device, revision=cmpa.revision,
            user_config=cmpa
        )
        self.cfpa_cfg = cfpa
        self.cfpa_obj = CFPA(
            device=cfpa.device, revision=cfpa.revision,
            user_config=cfpa
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
        splitted = key.split('.', maxsplit=1)
        register = self.cmpa_obj.registers.find_reg(splitted[0])
        if len(splitted) == 2:
            value = register.find_bitfield(splitted[1]).get_value()
        else:
            value = register.get_int_value()
        self.logger.debug(f"Extracted value {value:x}")

        return value

    def _cfpa_translate(self, key: str) -> int:
        """Handler for CFPA data."""
        self.logger.debug(f'Extracting value from {key}')
        splitted = key.split('.', maxsplit=1)
        register = self.cfpa_obj.registers.find_reg(splitted[0])
        if len(splitted) == 2:
            value = register.find_bitfield(splitted[1]).get_value()
        else:
            value = register.get_int_value()
        self.logger.debug(f"Extracted value {value:x}")

        return value

    def _util_translate(self, key: str) -> int:
        """Handler for Utils data."""
        values = {
            'isUDSKeyCodeValid': False
        }
        return values[key]
