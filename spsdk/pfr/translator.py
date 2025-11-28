#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR configuration translator utilities.

This module provides functionality for translating stringified configuration
keys into their corresponding values for PFR (Protected Flash Region) operations.
The Translator class handles conversion between human-readable configuration
parameters and their binary representations used in CFPA and CMPA structures.
"""

import logging
from typing import Optional

from spsdk.pfr.exceptions import SPSDKPfrcMissingConfigError
from spsdk.pfr.pfr import CFPA, CMPA

logger = logging.getLogger(__name__)


class Translator:
    """PFR register and key value translator.

    This class provides translation services for converting string-based register
    and key names into their corresponding numeric values. It supports CMPA and CFPA
    configuration data translation through dedicated handlers for different areas.
    """

    def __init__(
        self,
        cmpa: Optional[CMPA] = None,
        cfpa: Optional[CFPA] = None,
    ) -> None:
        """Initialize CMPA and CFPA data.

        :param cmpa: Configuration data loaded from CMPA config file.
        :param cfpa: Configuration data loaded from CFPA config file.
        """
        self.cmpa_obj = cmpa
        self.cfpa_obj = cfpa
        self.handlers = {
            "CMPA": self._cmpa_translate,
            "CFPA": self._cfpa_translate,
            "UTIL": self._util_translate,
        }

    def translate(self, key: str) -> int:
        """Translate register or generic key to its corresponding value.

        The method parses the key by splitting on the first dot to separate area and value
        designators, then uses the appropriate handler to retrieve the value.

        :param key: Register or key name in format "area.value" (e.g., "CFPA.BOOT_CFG").
        :return: Translated integer value for the given key.
        :raises SPSDKPfrcTranslationError: When configuration for given key is not defined.
        """
        area, value = key.split(".", maxsplit=1)
        logger.debug(f"Area designator: {area}")
        logger.debug(f"Register designator: {value}")
        return self.handlers[area](value)

    def _cmpa_translate(self, key: str) -> int:
        """Handler for CMPA data translation.

        Translates CMPA register or bitfield keys to their corresponding values.
        The key can reference either a complete register or a specific bitfield
        within a register using dot notation (register.bitfield).

        :param key: Register name or register.bitfield path to translate
        :raises SPSDKPfrcMissingConfigError: When CMPA configuration is not defined
        :return: Translated integer value from the specified register or bitfield
        """
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
        """Translate CFPA register or bitfield key to its numeric value.

        Extracts the value from a CFPA register or specific bitfield within a register.
        The key format supports both register-level access (e.g., "REGISTER_NAME") and
        bitfield-level access (e.g., "REGISTER_NAME.BITFIELD_NAME").

        :param key: Register name or register.bitfield path to extract value from
        :raises SPSDKPfrcMissingConfigError: CFPA configuration object is not defined
        :return: Extracted numeric value from the specified register or bitfield
        """
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
        """Handler for Utils data translation.

        Translates utility-related keys to their corresponding values from a predefined
        mapping dictionary.

        :param key: The utility key to translate (e.g., "isUDSKeyCodeValid").
        :raises KeyError: If the provided key is not found in the values mapping.
        :return: The translated value corresponding to the given key.
        """
        values = {"isUDSKeyCodeValid": False}
        return values[key]
