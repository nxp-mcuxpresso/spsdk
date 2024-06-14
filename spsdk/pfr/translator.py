#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Translator is responsible for converting stringified keys into values."""

import logging
from typing import Optional

from spsdk.pfr.exceptions import SPSDKPfrcMissingConfigError
from spsdk.pfr.pfr import CFPA, CMPA

logger = logging.getLogger(__name__)


class Translator:
    """Translates single strings (register/key names) into values."""

    def __init__(
        self,
        cmpa: Optional[CMPA] = None,
        cfpa: Optional[CFPA] = None,
    ) -> None:
        """Initialize CMPA and CFPA data.

        :param cmpa: configuration data loaded from CMPA config file
        :param cfpa: configuration data loaded from CFPA config file
        """
        self.cmpa_obj = cmpa
        self.cfpa_obj = cfpa
        self.handlers = {
            "CMPA": self._cmpa_translate,
            "CFPA": self._cfpa_translate,
            "UTIL": self._util_translate,
        }

    def translate(self, key: str) -> int:
        """Lookup register's (or generic key's) value.

        :param key: Register's (key's) stringified name
        :return: Register's (key's) value
        :raises SPSDKPfrcTranslationError: Raises when the configuration for given key is not defined
        """
        area, value = key.split(".", maxsplit=1)
        logger.debug(f"Area designator: {area}")
        logger.debug(f"Register designator: {value}")
        return self.handlers[area](value)

    def _cmpa_translate(self, key: str) -> int:
        """Handler for CMPA data."""
        if not self.cmpa_obj:
            raise SPSDKPfrcMissingConfigError(f"Cannot translate {key}. CMPA config not defined")
        logger.debug(f"Extracting value from {key}")
        splitted = key.split(".", maxsplit=1)
        register = self.cmpa_obj.registers.find_reg(splitted[0])
        if len(splitted) == 2:
            value = register.find_bitfield(splitted[1]).get_value()
        else:
            value = register.get_value()
        logger.debug(f"Extracted value {value:x}")

        return value

    def _cfpa_translate(self, key: str) -> int:
        """Handler for CFPA data."""
        if not self.cfpa_obj:
            raise SPSDKPfrcMissingConfigError(f"Cannot translate {key}. CFPA config not defined")
        logger.debug(f"Extracting value from {key}")
        splitted = key.split(".", maxsplit=1)
        register = self.cfpa_obj.registers.find_reg(splitted[0])
        if len(splitted) == 2:
            value = register.find_bitfield(splitted[1]).get_value()
        else:
            value = register.get_value()
        logger.debug(f"Extracted value {value:x}")

        return value

    def _util_translate(self, key: str) -> int:  # pylint: disable=no-self-use
        """Handler for Utils data."""
        values = {"isUDSKeyCodeValid": False}
        return values[key]
