#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK PFRC (Protected Flash Region Checker) testing module.

This module contains comprehensive test cases for the PFRC functionality,
including configuration validation, rule checking, and error handling for
NXP MCU protected flash regions.
"""

import os

import pytest
import ruamel.yaml

from spsdk.exceptions import SPSDKError
from spsdk.pfr.exceptions import SPSDKPfrError
from spsdk.pfr.pfr import CFPA, CMPA
from spsdk.pfr.pfrc import Pfrc, Rule, RulesList
from spsdk.utils.config import Config


def test_pfrc_without_any_config() -> None:
    """Test PFRC initialization without configuration parameters.

    Verifies that the Pfrc class constructor raises an appropriate error when
    instantiated without providing either CMPA or CFPA configuration parameters.

    :raises SPSDKPfrError: When no CMPA or CFPA configurations are specified.
    """
    with pytest.raises(SPSDKPfrError, match="No cmpa or cfpa configurations specified"):
        Pfrc()


def test_pfrc_with_unsupported_device(data_dir: str) -> None:
    """Test if PFRC raises an error when an unsupported device is provided.

    This test verifies that the PFRC constructor properly validates device support
    and raises an appropriate error when attempting to create a PFRC instance
    with a CFPA configuration for an unsupported device.

    :param data_dir: Directory path containing test data files
    :raises SPSDKError: Expected exception when unsupported device is used
    """
    cfpa_config_path = os.path.join(data_dir, "cfpa-lpc551x.yaml")
    cfpa_config = Config.create_from_file(cfpa_config_path)
    with pytest.raises(SPSDKError):
        Pfrc(cfpa=CFPA.load_from_config(cfpa_config))


def test_pfrc_with_cfpa_and_cmpa_configs(data_dir: str) -> None:
    """Test PFRC functionality with CFPA and CMPA configuration files.

    This test validates that PFRC can properly load and process both CFPA and CMPA
    configurations, load validation rules, and execute brick condition validation
    without any failures or skipped tests.

    :param data_dir: Directory path containing test configuration files
    :raises AssertionError: When validation fails or produces unexpected results
    """
    cfpa_config_path = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    cmpa_config_path = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    cmpa_config = Config.create_from_file(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    pfrc = Pfrc(cfpa=cfpa, cmpa=cmpa)
    rules = pfrc.load_rules()
    passed, failed, skipped = pfrc.validate_brick_conditions()
    assert len(failed) == 0
    assert len(skipped) == 0
    assert len(passed) == len(rules) - len(failed)


def test_pfrc_with_cfpa_config(data_dir: str) -> None:
    """Test PFRC validation with only CFPA configuration.

    This test verifies that PFRC correctly handles validation when only CFPA
    configuration is provided. It loads a default CFPA configuration, creates
    a PFRC instance, and validates that rules requiring CMPA data are properly
    skipped while CFPA-only rules pass validation.

    :param data_dir: Directory path containing test data files including CFPA configuration.
    """
    cfpa_config_path = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cfpa=cfpa)
    rules = pfrc.load_rules()
    rules_to_be_skipped: list[Rule] = [rule for rule in rules if "CMPA." in rule.cond]
    passed, failed, skipped = pfrc.validate_brick_conditions()

    assert len(skipped) == len(rules_to_be_skipped)
    for rule in skipped:
        assert rule in rules_to_be_skipped
    rules_to_be_passed: list[Rule] = [rule for rule in rules if rule not in rules_to_be_skipped]
    assert len(passed) == len(rules_to_be_passed)
    for rule in passed:
        assert rule in rules_to_be_passed
    assert len(failed) == 0


def test_loading_of_rules_with_additional_rules(data_dir: str) -> None:
    """Test loading of rules with additional rules functionality.

    Verifies that the Pfrc class correctly loads and combines default rules
    with additional custom rules from an external file. The test ensures
    that the total number of rules equals the sum of default and custom rules.

    :param data_dir: Directory path containing test data files including
                     CMPA configuration and custom rules files.
    """
    cmpa_config_path = os.path.join(data_dir, "cmpa_pfrc_lpc55s3x.yml")
    cmpa_config = Config.create_from_file(cmpa_config_path)
    pfrc = Pfrc(cmpa=CMPA.load_from_config(cmpa_config))
    default_rules = pfrc.load_rules()
    rules_path = os.path.join(data_dir, "rules.json")
    custom_rules = RulesList.load_from_file(rules_path)
    all_rules = pfrc.load_rules(additional_rules_file=rules_path)
    assert len(all_rules) == len(default_rules + custom_rules)


def test_pfrc_with_incorrect_rule(data_dir: str) -> None:
    """Test PFRC validation with incorrect rule configuration.

    Verifies that PFRC properly handles and raises appropriate errors when
    provided with malformed or incorrect rule definitions in the rules file.

    :param data_dir: Directory path containing test data files including CFPA configuration and incorrect rules file.
    :raises SPSDKPfrError: When unable to parse the incorrect rule file.
    """
    cfpa_config_path = os.path.join(data_dir, "cfpa_pfrc_lpc55s3x.yml")
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cfpa=cfpa)
    rules_path = os.path.join(data_dir, "rules_incorrect_rule.json")
    with pytest.raises(SPSDKPfrError, match="ERROR: Unable to parse"):
        pfrc.validate_brick_conditions(additional_rules_file=rules_path)


def test_pfrc_with_non_existing_register(data_dir: str) -> None:
    """Test the validation with non-existing register.

    This test verifies that the PFRC validation properly handles and raises
    an SPSDKPfrError when attempting to validate brick conditions with rules
    that reference non-existing registers.

    :param data_dir: Directory path containing test data files including CMPA configuration and rules files.
    :raises SPSDKPfrError: When validation encounters rules referencing non-existing registers.
    """
    cmpa_config_path = os.path.join(data_dir, "cmpa_pfrc_lpc55s3x.yml")
    cmpa_config = Config.create_from_file(cmpa_config_path)
    pfrc = Pfrc(cmpa=CMPA.load_from_config(cmpa_config))
    rules_path = os.path.join(data_dir, "rules_non_existing_register.json")
    with pytest.raises(SPSDKPfrError):
        pfrc.validate_brick_conditions(additional_rules_file=rules_path)


@pytest.mark.parametrize(
    "nr_of_failed,cmpa_pin_bitfields,cfpa_pin_bitfields",
    [
        (0, [], []),
        (1, [], [("FA_CMD_EN", 1)]),
        (0, [("FA_CMD_EN", 1)], []),
        (0, [("FA_CMD_EN", 1)], [("FA_CMD_EN", 1)]),
        (1, [("FA_CMD_EN", 1)], [("ISP_CMD_EN", 1)]),
    ],
)
def test_rule_1_1(
    tmp_path: str,
    data_dir: str,
    nr_of_failed: int,
    cmpa_pin_bitfields: list[tuple[str, int]],
    cfpa_pin_bitfields: list[tuple[str, int]],
) -> None:
    """Test PFR rule 1.1 validation for DCFG_CC_SOCU pin configuration.

    Validates that non-zero CFPA.DCFG_CC_SOCU_NS_PIN bits combined with zero
    CMPA.DCFG_CC_SOCU_PIN bits properly trigger PFR rule 1.1 violation detection.
    The test creates temporary CMPA and CFPA configuration files with specified
    bitfield values and verifies the expected number of validation failures.

    :param tmp_path: Temporary directory path for output files.
    :param data_dir: Directory path containing test data templates.
    :param nr_of_failed: Expected number of validation failures.
    :param cmpa_pin_bitfields: List of tuples containing CMPA bitfield names and values.
    :param cfpa_pin_bitfields: List of tuples containing CFPA bitfield names and values.
    """
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    cmpa_config, cmpa_ind, cmpa_bsi = ruamel.yaml.util.load_yaml_guess_indent(
        open(cmpa_config_template)
    )
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    cfpa_config, cfpa_ind, cfpa_bsi = ruamel.yaml.util.load_yaml_guess_indent(
        open(cfpa_config_template)
    )

    for bitfield in cmpa_pin_bitfields:
        cmpa_config["settings"]["DCFG_CC_SOCU_PIN"]["bitfields"][bitfield[0]] = bitfield[1]
    for bitfield in cfpa_pin_bitfields:
        cfpa_config["settings"]["DCFG_CC_SOCU_NS_PIN"]["bitfields"][bitfield[0]] = bitfield[1]

    cmpa_config_path = os.path.join(tmp_path, "output_cmpa.yaml")
    with open(cmpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=cmpa_ind, sequence=cmpa_ind, offset=cmpa_bsi)
        yaml.dump(cmpa_config, fp)
    cfpa_config_path = os.path.join(tmp_path, "output_cfpa.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=cfpa_ind, sequence=cfpa_ind, offset=cfpa_bsi)
        yaml.dump(cfpa_config, fp)
    cmpa_config = Config.create_from_file(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cmpa=cmpa, cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    assert len(failed) == nr_of_failed
    for fail in failed:
        assert "Never write any non-zero configuration" in fail.desc


@pytest.mark.parametrize(
    "nr_of_failed,cmpa_dflt_bitfields,cfpa_dflt_bitfields",
    [
        (0, [], []),
        (1, [], [("FA_CMD_EN", 1)]),
        (0, [("FA_CMD_EN", 1)], []),
        (0, [("FA_CMD_EN", 1)], [("FA_CMD_EN", 1)]),
        (1, [("FA_CMD_EN", 1)], [("ISP_CMD_EN", 1)]),
    ],
)
def test_rule_1_2(
    tmp_path: str,
    data_dir: str,
    nr_of_failed: int,
    cmpa_dflt_bitfields: list[tuple[str, int]],
    cfpa_dflt_bitfields: list[tuple[str, int]],
) -> None:
    """Test PFR validation rule 1.2 for DCFG_CC_SOCU configuration conflicts.

    Validates that non-zero CFPA.DCFG_CC_SOCU_NS_DFLT bits combined with zero
    CMPA.DCFG_CC_SOCU_DFLT bits properly trigger validation rule 1.2 failure.
    The test creates CMPA and CFPA configurations with specified bitfield values,
    runs PFR validation, and verifies the expected number of rule 1.2 failures.

    :param tmp_path: Temporary directory path for output files.
    :param data_dir: Directory path containing test data templates.
    :param nr_of_failed: Expected number of rule 1.2 validation failures.
    :param cmpa_dflt_bitfields: List of tuples containing CMPA bitfield names and values to set.
    :param cfpa_dflt_bitfields: List of tuples containing CFPA bitfield names and values to set.
    """
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    cmpa_config, cmpa_ind, cmpa_bsi = ruamel.yaml.util.load_yaml_guess_indent(
        open(cmpa_config_template)
    )
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    cfpa_config, cfpa_ind, cfpa_bsi = ruamel.yaml.util.load_yaml_guess_indent(
        open(cfpa_config_template)
    )

    for bitfield in cmpa_dflt_bitfields:
        cmpa_config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"][bitfield[0]] = bitfield[1]
    for bitfield in cfpa_dflt_bitfields:
        cfpa_config["settings"]["DCFG_CC_SOCU_NS_DFLT"]["bitfields"][bitfield[0]] = bitfield[1]

    cmpa_config_path = os.path.join(tmp_path, "output_cmpa.yaml")
    with open(cmpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=cmpa_ind, sequence=cmpa_ind, offset=cmpa_bsi)
        yaml.dump(cmpa_config, fp)
    cfpa_config_path = os.path.join(tmp_path, "output_cfpa.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=cfpa_ind, sequence=cfpa_ind, offset=cfpa_bsi)
        yaml.dump(cfpa_config, fp)
    cmpa_config = Config.create_from_file(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cmpa=cmpa, cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    # Some other rules may be broken with this config
    failed_filtered = [fail for fail in failed if fail.req_id == "1.2"]
    assert len(failed_filtered) == nr_of_failed
    for fail in failed_filtered:
        assert "Never write any non-zero configuration" in fail.desc


@pytest.mark.parametrize(
    "nr_of_failed,pin_bitfields,dflt_bitfields",
    [
        (0, [], []),
        (0, [("NIDEN", 1), ("INVERSE_VALUE", 65534)], [("NIDEN", 1), ("INVERSE_VALUE", 65534)]),
        (
            2,
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65534)],
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65534)],
        ),
        (
            0,
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65532)],
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65532)],
        ),
        (
            1,
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65534)],
            [("NIDEN", 1), ("INVERSE_VALUE", 65534)],
        ),
    ],
)
def test_cmpa_inverse_bits_rules(
    tmp_path: str,
    data_dir: str,
    nr_of_failed: int,
    pin_bitfields: list[tuple[str, int]],
    dflt_bitfields: list[tuple[str, int]],
) -> None:
    """Test the CMPA rules regarding inverse bits are detected: 1.3, 1.4.

    This test validates that the PFR checker correctly identifies violations of CMPA
    inverse bit rules by injecting error values into PIN and DFLT bitfields and
    verifying the expected number of validation failures.

    :param tmp_path: Temporary directory path for test files.
    :param data_dir: Directory path containing test data files.
    :param nr_of_failed: Expected number of validation failures.
    :param pin_bitfields: List of tuples containing PIN bitfield names and values to inject.
    :param dflt_bitfields: List of tuples containing DFLT bitfield names and values to inject.
    """
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default_full.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cmpa_config_template))
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cmpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cmpa_config = Config.create_from_file(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    # Inject error values
    for bitfield in pin_bitfields:
        cmpa.registers.find_reg("DCFG_CC_SOCU_PIN").find_bitfield(bitfield[0]).set_value(
            bitfield[1], raw=True
        )
    for bitfield in dflt_bitfields:
        cmpa.registers.find_reg("DCFG_CC_SOCU_DFLT").find_bitfield(bitfield[0]).set_value(
            bitfield[1], raw=True
        )
    pfrc = Pfrc(cmpa=cmpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    assert len(failed) == nr_of_failed
    for fail in failed:
        assert "Inverse values are generated automatically based on configuration." in fail.msg


@pytest.mark.parametrize(
    "nr_of_failed,pin_bitfields,dflt_bitfields",
    [
        (0, [], []),
        (0, [("NIDEN", 1), ("INVERSE_VALUE", 65534)], [("NIDEN", 1), ("INVERSE_VALUE", 65534)]),
        (
            2,
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65534)],
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65534)],
        ),
        (
            0,
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65532)],
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65532)],
        ),
        (
            1,
            [("NIDEN", 1), ("DBGEN", 1), ("INVERSE_VALUE", 65534)],
            [("NIDEN", 1), ("INVERSE_VALUE", 65534)],
        ),
    ],
)
def test_cfpa_inverse_bits_rules(
    tmp_path: str, data_dir: str, nr_of_failed: int, pin_bitfields: list, dflt_bitfields: list
) -> None:
    """Test the CFPA rules regarding inverse bits are detected: 1.5, 1.6.

    This test validates that the PFRC (Protected Flash Region Checker) properly
    detects violations of inverse bit rules in CFPA (Customer Field Programmable Area)
    configuration. It injects error values into PIN and DFLT bitfields and verifies
    that the expected number of validation failures are detected.

    :param tmp_path: Temporary directory path for test files.
    :param data_dir: Directory path containing test data files.
    :param nr_of_failed: Expected number of validation failures.
    :param pin_bitfields: List of tuples containing PIN bitfield names and values to inject.
    :param dflt_bitfields: List of tuples containing DFLT bitfield names and values to inject.
    """
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default_full.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))
    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)

    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    # Inject error values
    for bitfield in pin_bitfields:
        cfpa.registers.find_reg("DCFG_CC_SOCU_NS_PIN").find_bitfield(bitfield[0]).set_value(
            bitfield[1], raw=True
        )
    for bitfield in dflt_bitfields:
        cfpa.registers.find_reg("DCFG_CC_SOCU_NS_DFLT").find_bitfield(bitfield[0]).set_value(
            bitfield[1], raw=True
        )
    pfrc = Pfrc(cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    assert len(failed) == nr_of_failed
    for fail in failed:
        assert "Inverse values are generated automatically based on configuration." in fail.msg


@pytest.mark.parametrize(
    "test_pass,pin_value,dflt_value,pin_bitfield,dflt_bitfield",
    [
        (True, 0, 0, "NIDEN", "NIDEN"),
        (True, 1, 0, "NIDEN", "NIDEN"),
        (False, 0, 1, "NIDEN", "NIDEN"),
        (True, 1, 1, "NIDEN", "NIDEN"),
        (False, 1, 1, "NIDEN", "DBGEN"),
    ],
)
def test_cmpa_invalid_pin_dflt_configuration_rules(
    tmp_path: str,
    data_dir: str,
    test_pass: bool,
    pin_value: int,
    dflt_value: int,
    pin_bitfield: str,
    dflt_bitfield: str,
) -> None:
    """Test CMPA rules for invalid pin/default configuration combinations.

    This test validates rule 1.7 which checks for invalid bit combinations between
    DCFG_CC_SOCU_PIN and DCFG_CC_SOCU_DFLT bitfields. It creates a temporary CMPA
    configuration with specified pin and default values, then validates whether
    the brick conditions are properly detected.

    :param tmp_path: Temporary directory path for test files.
    :param data_dir: Directory containing test data files.
    :param test_pass: Expected test result - True if validation should pass, False if it should fail.
    :param pin_value: Value to set for the pin bitfield.
    :param dflt_value: Value to set for the default bitfield.
    :param pin_bitfield: Name of the pin bitfield to modify.
    :param dflt_bitfield: Name of the default bitfield to modify.
    """
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cmpa_config_template))
    config["settings"]["DCFG_CC_SOCU_PIN"]["bitfields"][pin_bitfield] = pin_value
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"][dflt_bitfield] = dflt_value
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cmpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cmpa_config = Config.create_from_file(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    pfrc = Pfrc(cmpa=cmpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    if test_pass:
        assert len(failed) == 0
    else:
        assert len(failed) == 1
        assert "Invalid bit combination." in failed[0].msg


@pytest.mark.parametrize(
    "test_pass,pin_value,dflt_value,pin_bitfield,dflt_bitfield",
    [
        (True, 0, 0, "NIDEN", "NIDEN"),
        (True, 1, 0, "NIDEN", "NIDEN"),
        (False, 0, 1, "NIDEN", "NIDEN"),
        (True, 1, 1, "NIDEN", "NIDEN"),
        (False, 1, 1, "NIDEN", "DBGEN"),
    ],
)
def test_cfpa_invalid_pin_dflt_configuration_rules(
    tmp_path: str,
    data_dir: str,
    test_pass: bool,
    pin_value: int,
    dflt_value: int,
    pin_bitfield: str,
    dflt_bitfield: str,
) -> None:
    """Test CFPA rules for invalid pin/default configuration combinations.

    This test validates the CFPA (Customer Field Programmable Area) brick condition
    rules specifically for invalid pin/default configuration scenarios (rule 1.8).
    It creates a temporary YAML configuration file with specified pin and default
    values, then validates whether the configuration should pass or fail based on
    the expected test outcome.

    :param tmp_path: Temporary directory path for creating test files.
    :param data_dir: Directory path containing test data files.
    :param test_pass: Expected test outcome - True if validation should pass, False if it should fail.
    :param pin_value: Value to set for the pin configuration.
    :param dflt_value: Value to set for the default configuration.
    :param pin_bitfield: Name of the pin bitfield to modify in the configuration.
    :param dflt_bitfield: Name of the default bitfield to modify in the configuration.
    """
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))
    config["settings"]["DCFG_CC_SOCU_NS_PIN"]["bitfields"][pin_bitfield] = pin_value
    config["settings"]["DCFG_CC_SOCU_NS_DFLT"]["bitfields"][dflt_bitfield] = dflt_value
    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    if test_pass:
        assert len(failed) == 0
    else:
        assert len(failed) == 1
        assert "Invalid bit combination." in failed[0].msg


@pytest.mark.parametrize(
    "test_pass,cmpa_prog_in_progress_value",
    [
        (True, 0x00000000),
        (False, 0x00000001),
        (False, 0xA0000000),
    ],
)
def test_cmpa_prog_in_progress_rule(
    tmp_path: str, data_dir: str, test_pass: bool, cmpa_prog_in_progress_value: int
) -> None:
    """Test CMPA_PROG_IN_PROGRESS validation rule.

    This test verifies that the PFRC validation correctly enforces the rule that
    CMPA_PROG_IN_PROGRESS must always be set to 0 (rule 2.1). It creates a CFPA
    configuration with a specified CMPA_PROG_IN_PROGRESS value and validates
    the brick conditions.

    :param tmp_path: Temporary directory path for test files
    :param data_dir: Directory containing test data files
    :param test_pass: Whether the test should pass (True) or fail (False)
    :param cmpa_prog_in_progress_value: Value to set for CMPA_PROG_IN_PROGRESS field
    """
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))
    config["settings"]["CMPA_PROG_IN_PROGRESS"]["value"] = cmpa_prog_in_progress_value
    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    if test_pass:
        assert len(failed) == 0
    else:
        assert len(failed) == 1
        assert "The CMPA_PROG_IN_PROGRESS must be set to 0" in failed[0].msg


@pytest.mark.parametrize(
    "test_pass,vendor_usage_value,inverse_value",
    [
        (True, 65535, 0),
        (True, 0, 65535),
        (False, 1, 65535),
        (False, 32, 65500),
    ],
)
def test_vendor_usage_rule(
    tmp_path: str, data_dir: str, test_pass: bool, vendor_usage_value: int, inverse_value: int
) -> None:
    """Test CFPA rules for inverse bits validation in VENDOR_USAGE register.

    Validates that PFRC correctly detects mismatched inverse bits in the VENDOR_USAGE
    register according to rule 5.1. The test injects specific values into the
    DBG_VENDOR_USAGE and INVERSE_VALUE bitfields and verifies the validation results.

    :param tmp_path: Temporary directory path for test files
    :param data_dir: Directory containing test data files
    :param test_pass: Expected test outcome - True if validation should pass, False if it should fail
    :param vendor_usage_value: Value to inject into DBG_VENDOR_USAGE bitfield
    :param inverse_value: Value to inject into INVERSE_VALUE bitfield
    """
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default_full.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))

    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cfpa_config = Config.create_from_file(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    # Inject error values
    cfpa.registers.find_reg("VENDOR_USAGE").find_bitfield("DBG_VENDOR_USAGE").set_value(
        vendor_usage_value, raw=True
    )
    cfpa.registers.find_reg("VENDOR_USAGE").find_bitfield("INVERSE_VALUE").set_value(
        inverse_value, raw=True
    )
    pfrc = Pfrc(cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    if test_pass:
        assert len(failed) == 0
    else:
        assert len(failed) == 1
        assert "Inverse values are generated automatically based on configuration." in failed[0].msg
