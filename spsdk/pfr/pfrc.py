#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR brick-condition validation utilities.

This module provides functionality for checking and validating brick-conditions
in Protected Flash Region (PFR) settings, including rule definitions and
configuration validation for CFPA and CMPA regions.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from spsdk.pfr.exceptions import SPSDKPfrcMissingConfigError, SPSDKPfrConfigError
from spsdk.pfr.pfr import CFPA, CMPA, SPSDKPfrError
from spsdk.pfr.processor import Processor
from spsdk.pfr.translator import Translator
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import load_configuration

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """PFR rule definition container.

    This class represents a single rule used in Protected Flash Region (PFR)
    configuration, containing the rule identifier, description, message, and
    condition for validation purposes.
    """

    req_id: str
    desc: str
    msg: str
    cond: str


class RulesList(list[Rule]):
    """SPSDK PFR Rules List container.

    This class extends the built-in list to provide specialized functionality for managing
    PFR (Protected Flash Region) rules. It offers convenient methods for loading rules
    from configuration files and supports both single file and multiple file operations.
    """

    @staticmethod
    def load_from_files_list(rules_file_list: list) -> "RulesList":
        """Load the rules from list of files.

        The method loads rules from multiple configuration files and combines them into a single
        RulesList object.

        :param rules_file_list: A list of paths to configuration files containing rules to be loaded.
        :return: RulesList object with loaded rules.
        """
        rules_list = RulesList()
        for rules_file in rules_file_list:
            rules = RulesList.load_from_file(rules_file)
            rules_list.extend(rules)
        return rules_list

    @staticmethod
    def load_from_file(rules_file: str) -> "RulesList":
        """Load the rules from a single file.

        The method loads rules from a configuration file and creates a RulesList object
        containing all the parsed rules.

        :param rules_file: Path to a configuration file containing rules to be loaded.
        :raises SPSDKPfrConfigError: No rules found in the configuration file.
        :return: RulesList object with loaded rules.
        """
        rules_dict: dict[str, list[dict]] = load_configuration(rules_file)
        if "rules" not in rules_dict:
            raise SPSDKPfrConfigError("No rules found in the configuration file")
        return RulesList(Rule(**rule) for rule in rules_dict["rules"])


class Pfrc:
    """SPSDK PFR Conditions Checker.

    This class validates Protected Flash Region (PFR) configurations by checking brick conditions
    and rules against CMPA and CFPA configuration data to ensure secure provisioning compliance.
    """

    def __init__(
        self,
        cmpa: Optional[CMPA] = None,
        cfpa: Optional[CFPA] = None,
    ) -> None:
        """Initialize PFRC instance with CMPA and/or CFPA configurations.

        Creates a new PFRC (Protected Flash Region Checker) instance that can handle
        either CMPA (Customer Manufacturing Programming Area) or CFPA (Customer Field
        Programming Area) configurations, or both. The instance validates the chip family
        compatibility and initializes the database connection.

        :param cmpa: CMPA configuration data loaded from config file, defaults to None
        :param cfpa: CFPA configuration data loaded from config file, defaults to None
        :raises SPSDKPfrError: No configuration is provided
        :raises SPSDKPfrConfigError: Problem with PFR configuration(s) occurred
        """
        if not (cmpa or cfpa):
            raise SPSDKPfrError("No cmpa or cfpa configurations specified")
        self.cmpa = cmpa
        self.cfpa = cfpa

        self.chip_family = cmpa.family if cmpa else cfpa.family  # type: ignore
        pfrc_devices = self.get_supported_families(True)
        if not self.chip_family or self.chip_family.name not in [x.name for x in pfrc_devices]:
            raise SPSDKPfrConfigError(
                f"Chip family from configuration is not supported: {self.chip_family} "
                f"Supported families:{self.get_supported_families()}"
            )

        self.db = get_db(self.chip_family)

    @staticmethod
    def get_supported_families(include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for PFR operations.

        Returns a list of device families that have PFR (Protected Flash Region) support
        by checking for available PFRC rules in the database.

        :param include_predecessors: Include predecessor family names in the result list.
        :return: List of supported families with PFR capabilities.
        """
        pfr_devices = get_families(DatabaseManager.PFR, include_predecessors=include_predecessors)
        ret = []
        for dev in pfr_devices:
            pfrc_rules = get_db(dev).get_list(DatabaseManager.PFR, "rules", [])
            if pfrc_rules:
                ret.append(dev)
        return ret

    def validate_brick_conditions(
        self, additional_rules_file: Optional[str] = None
    ) -> tuple[RulesList, RulesList, RulesList]:
        """Validate brick conditions for the specified configuration.

        This method processes brick condition rules against the current CMPA and CFPA
        configuration to determine which conditions would cause device bricking.

        :param additional_rules_file: Path to additional rules file to supplement
            default rules, defaults to None
        :return: Tuple containing (passed_rules, failed_rules, skipped_rules) where
            each element is a RulesList containing the respective rule results
        :raises SPSDKPfrError: When brick condition validation fails due to parsing
            errors, identifier lookup failures, or evaluation errors
        """
        rules = self.load_rules(additional_rules_file)
        translator = Translator(cmpa=self.cmpa, cfpa=self.cfpa)
        processor = Processor(translator=translator)
        try:
            failed_rules, passed_rules, skipped_rules = RulesList(), RulesList(), RulesList()
            for rule in rules:
                logger.debug(f"Processing the brick condition: {rule.req_id}: {rule.desc} ")
                try:
                    result, condition = processor.process(rule.cond)
                except SPSDKPfrcMissingConfigError as e:
                    skipped_rules.append(rule)
                    logger.debug(f"Brick condition not translated: {e}")
                    continue
                logger.debug(f"Brick condition '{rule.cond}' translated to '{condition}'")
                if result:
                    failed_rules.append(rule)
                    logger.warning(f"FAIL: you are going to brick your device\n{rule.msg}")
                else:
                    passed_rules.append(rule)
                    logger.info("OK: Brick condition not fulfilled")
        except SyntaxError as e:
            raise SPSDKPfrError(f"\nERROR: Unable to parse: '{e}'") from e
        except (KeyError, ValueError, TypeError) as e:
            raise SPSDKPfrError(f"\nERROR: Unable to lookup identifier: {e}") from e
        except Exception as e:  # pylint: disable=broad-except
            raise SPSDKPfrError(f"Error e({e}) while evaluating {rule.cond}") from e
        return passed_rules, failed_rules, skipped_rules

    def load_rules(self, additional_rules_file: Optional[str] = None) -> RulesList:
        """Load rules for device family with optional additional user rules.

        The method retrieves default rules from the database for the current device family
        and optionally appends additional rules from a user-specified file.

        :param additional_rules_file: Path to additional rules file to append to default rules.
        :return: Loaded rules as RulesList object containing all applicable rules.
        """
        rules_files = self.db.get_list(DatabaseManager.PFR, "rules")
        rules_files = [self.db.device.create_file_path(rules_file) for rules_file in rules_files]
        if additional_rules_file:
            rules_files.append(additional_rules_file)
        return RulesList.load_from_files_list(rules_files)
