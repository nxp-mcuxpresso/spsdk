#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides support for checking the brick-conditions in PFR settings."""

import logging
from dataclasses import dataclass
from typing import Optional

from spsdk.pfr.exceptions import SPSDKPfrcMissingConfigError, SPSDKPfrConfigError
from spsdk.pfr.pfr import CFPA, CMPA, SPSDKPfrError
from spsdk.pfr.processor import Processor
from spsdk.pfr.translator import Translator
from spsdk.utils.database import DatabaseManager, get_db, get_families
from spsdk.utils.misc import load_configuration

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Dataclass holding information about individual rule."""

    req_id: str
    desc: str
    msg: str
    cond: str


class RulesList(list[Rule]):
    """List of rules."""

    @staticmethod
    def load_from_files_list(rules_file_list: list) -> "RulesList":
        """Load the rules from list of files.

        :param rules_file_list: A list of paths to configuration files containing rules to be loaded
        :returns RulesList object with loaded rules
        """
        rules_list = RulesList()
        for rules_file in rules_file_list:
            rules = RulesList.load_from_file(rules_file)
            rules_list.extend(rules)
        return rules_list

    @staticmethod
    def load_from_file(rules_file: str) -> "RulesList":
        """Load the rules from a single file.

        :param rules_file: A path to a configuration file containing rules to be loaded
        :returns RulesList object with loaded rules
        """
        rules_dict: dict[str, list[dict]] = load_configuration(rules_file)
        if "rules" not in rules_dict:
            raise SPSDKPfrConfigError("No rules found in the configuration file")
        return RulesList(Rule(**rule) for rule in rules_dict["rules"])


class Pfrc:
    """Class responsible for checking of the conditions."""

    def __init__(
        self,
        cmpa: Optional[CMPA] = None,
        cfpa: Optional[CFPA] = None,
    ) -> None:
        """Initialize an instance.

        :param cmpa: configuration data loaded from CMPA config file, defaults to None
        :param cfpa: configuration data loaded from CFPA config file, defaults to None
        :raises SPSDKPfrError: No configuration is provided
        :raises SPSDKPfrConfigError: Problem with PFR configuration(s) occurred
        """
        if not (cmpa or cfpa):
            raise SPSDKPfrError("No cmpa or cfpa configurations specified")
        self.cmpa = cmpa
        self.cfpa = cfpa

        self.chip_family = cmpa.family if cmpa else cfpa.family  # type: ignore
        pfrc_devices = self.get_supported_families()
        pfrc_devices += list(
            DatabaseManager().quick_info.devices.get_predecessors(pfrc_devices).keys()
        )
        if not self.chip_family or self.chip_family not in pfrc_devices:
            raise SPSDKPfrConfigError(
                f"Chip family from configuration is not supported: {self.chip_family} "
                f"Supported families:{self.get_supported_families()}"
            )

        self.db = get_db(self.chip_family, "latest")

    @staticmethod
    def get_supported_families() -> list[str]:
        """Return list of supported families.

        :return: List of supported families.
        """
        pfr_devices = get_families(DatabaseManager.PFR)
        ret = []
        for dev in pfr_devices:
            pfrc_rules = get_db(dev, "latest").get_list(DatabaseManager.PFR, "rules", [])
            if pfrc_rules:
                ret.append(dev)
        return ret

    def validate_brick_conditions(
        self, additional_rules_file: Optional[str] = None
    ) -> tuple[RulesList, RulesList, RulesList]:
        """The method validates the brick conditions for specified configuration.

        :param additional_rules_file: Additional rules file, defaults to None
        :returns Tuple with passed, failed and skipped rules as a RulesList
        :raises SPSDKPfrError: Brick condition validation failed
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
        """The function loads the rules for family and optionally add additional rules from user.

        :param additional_rules_file: Additional rules file, defaults to None
        :return: Loaded rules in list of dictionaries.
        """
        rules_files = self.db.get_list(DatabaseManager.PFR, "rules")
        rules_files = [self.db.device.create_file_path(rules_file) for rules_file in rules_files]
        if additional_rules_file:
            rules_files.append(additional_rules_file)
        return RulesList.load_from_files_list(rules_files)
