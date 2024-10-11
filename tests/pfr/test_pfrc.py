#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""The test file for PFRC API."""

import os

import pytest
import ruamel.yaml

from spsdk.exceptions import SPSDKError
from spsdk.pfr.exceptions import SPSDKPfrConfigError, SPSDKPfrError
from spsdk.pfr.pfr import CFPA, CMPA
from spsdk.pfr.pfrc import Pfrc, RulesList
from spsdk.utils.misc import load_configuration


def test_pfrc_without_any_config():
    """Test if pfrc raises an error if no config is provided"""
    with pytest.raises(SPSDKPfrError, match="No cmpa or cfpa configurations specified"):
        Pfrc()


def test_pfrc_with_unsupported_device(data_dir):
    """Test if pfrc raises an error if unsupported device is provided"""
    cfpa_config_path = os.path.join(data_dir, "cfpa-lpc551x.yaml")
    cfpa_config = load_configuration(cfpa_config_path)
    with pytest.raises(SPSDKError):
        Pfrc(cfpa=CFPA.load_from_config(cfpa_config))


def test_pfrc_with_cfpa_and_cmpa_configs(data_dir):
    """Test the PFCA with cfpa and cmpa config."""
    cfpa_config_path = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    cfpa_config = load_configuration(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    cmpa_config_path = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    cmpa_config = load_configuration(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    pfrc = Pfrc(cfpa=cfpa, cmpa=cmpa)
    rules = pfrc.load_rules()
    passed, failed, skipped = pfrc.validate_brick_conditions()
    assert len(failed) == 0
    assert len(skipped) == 0
    assert len(passed) == len(rules) - len(failed)


def test_pfrc_with_cfpa_config(data_dir):
    """Test the PFCA with only cfpa config."""
    cfpa_config_path = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    cfpa_config = load_configuration(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cfpa=cfpa)
    rules = pfrc.load_rules()
    rules_to_be_skipped = RulesList(rule for rule in rules if "CMPA." in rule.cond)
    passed, failed, skipped = pfrc.validate_brick_conditions()

    assert len(skipped) == len(rules_to_be_skipped)
    for rule in skipped:
        assert rule in rules_to_be_skipped
    rules_to_be_passed = RulesList(rule for rule in rules if rule not in rules_to_be_skipped)
    assert len(passed) == len(rules_to_be_passed)
    for rule in passed:
        assert rule in rules_to_be_passed
    assert len(failed) == 0


def test_loading_of_rules_with_additional_rules(data_dir):
    """Test the integrity of rules data."""
    cmpa_config_path = os.path.join(data_dir, "cmpa_pfrc_lpc55s3x.yml")
    cmpa_config = load_configuration(cmpa_config_path)
    pfrc = Pfrc(cmpa=CMPA.load_from_config(cmpa_config))
    default_rules = pfrc.load_rules()
    rules_path = os.path.join(data_dir, "rules.json")
    custom_rules = RulesList.load_from_file(rules_path)
    all_rules = pfrc.load_rules(additional_rules_file=rules_path)
    assert len(all_rules) == len(default_rules + custom_rules)


def test_pfrc_with_incorrect_rule(data_dir):
    """Test the PFCA with incorrect rule."""
    cfpa_config_path = os.path.join(data_dir, "cfpa_pfrc_lpc55s3x.yml")
    cfpa_config = load_configuration(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cfpa=cfpa)
    rules_path = os.path.join(data_dir, "rules_incorrect_rule.json")
    with pytest.raises(SPSDKPfrError, match="ERROR: Unable to parse"):
        pfrc.validate_brick_conditions(additional_rules_file=rules_path)


def test_pfrc_with_non_existing_register(data_dir):
    """Test the validation with non-existing register."""
    cmpa_config_path = os.path.join(data_dir, "cmpa_pfrc_lpc55s3x.yml")
    cmpa_config = load_configuration(cmpa_config_path)
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
def test_rule_1_1(tmp_path, data_dir, nr_of_failed, cmpa_pin_bitfields, cfpa_pin_bitfields):
    """Test that non-zero CFPA.DCFG_CC_SOCU_NS_PIN bit and zero CMPA.DCFG_CC_SOCU_PIN bit are breaking the rule: 1.1"""
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
    cmpa_config = load_configuration(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    cfpa_config = load_configuration(cfpa_config_path)
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
def test_rule_1_2(tmp_path, data_dir, nr_of_failed, cmpa_dflt_bitfields, cfpa_dflt_bitfields):
    """Test that non-zero CFPA.DCFG_CC_SOCU_NS_DFLT bit and zero CMPA.DCFG_CC_SOCU_DFLT bit are breaking the rule: 1.2"""
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
    cmpa_config = load_configuration(cmpa_config_path)
    cmpa = CMPA.load_from_config(cmpa_config)
    cfpa_config = load_configuration(cfpa_config_path)
    cfpa = CFPA.load_from_config(cfpa_config)
    pfrc = Pfrc(cmpa=cmpa, cfpa=cfpa)
    _, failed, _ = pfrc.validate_brick_conditions()
    # Some other rules may be broken with this config
    failed = [fail for fail in failed if fail.req_id == "1.2"]
    assert len(failed) == nr_of_failed
    for fail in failed:
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
def test_cmpa_inverse_bits_rules(tmp_path, data_dir, nr_of_failed, pin_bitfields, dflt_bitfields):
    """Test the CMPA rules regarding inverse bits are detected: 1.3, 1.4"""
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default_full.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cmpa_config_template))
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cmpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cmpa_config = load_configuration(cmpa_config_path)
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
def test_cfpa_inverse_bits_rules(tmp_path, data_dir, nr_of_failed, pin_bitfields, dflt_bitfields):
    """Test the CFPA rules regarding inverse bits are detected: 1.5, 1.6"""
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default_full.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))
    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)

    cfpa_config = load_configuration(cfpa_config_path)
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
    tmp_path, data_dir, test_pass, pin_value, dflt_value, pin_bitfield, dflt_bitfield
):
    """Test the CMPA rules regarding invalid pin/dflt configuration: 1.7"""
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cmpa_config_template))
    config["settings"]["DCFG_CC_SOCU_PIN"]["bitfields"][pin_bitfield] = pin_value
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"][dflt_bitfield] = dflt_value
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cmpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cmpa_config = load_configuration(cmpa_config_path)
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
    tmp_path, data_dir, test_pass, pin_value, dflt_value, pin_bitfield, dflt_bitfield
):
    """Test the CFPA rules regarding invalid pin/dflt configuration: 1.8"""
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))
    config["settings"]["DCFG_CC_SOCU_NS_PIN"]["bitfields"][pin_bitfield] = pin_value
    config["settings"]["DCFG_CC_SOCU_NS_DFLT"]["bitfields"][dflt_bitfield] = dflt_value
    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cfpa_config = load_configuration(cfpa_config_path)
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
def test_cmpa_prog_in_progress_rule(tmp_path, data_dir, test_pass, cmpa_prog_in_progress_value):
    """Test that CMPA_PROG_IN_PROGRESS is always 0: 2.1"""
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))
    config["settings"]["CMPA_PROG_IN_PROGRESS"]["value"] = cmpa_prog_in_progress_value
    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cfpa_config = load_configuration(cfpa_config_path)
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
def test_vendor_usage_rule(tmp_path, data_dir, test_pass, vendor_usage_value, inverse_value):
    """Test the CFPA rules regarding inverse bits of VENDOR_USAGE register are detected: 5.1"""
    cfpa_config_template = os.path.join(data_dir, "cfpa_lpc55s3x_default_full.yaml")
    config, ind, bsi = ruamel.yaml.util.load_yaml_guess_indent(open(cfpa_config_template))

    cfpa_config_path = os.path.join(tmp_path, "output.yaml")
    with open(cfpa_config_path, "w") as fp:
        yaml = ruamel.yaml.YAML()
        yaml.indent(mapping=ind, sequence=ind, offset=bsi)
        yaml.dump(config, fp)
    cfpa_config = load_configuration(cfpa_config_path)
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
