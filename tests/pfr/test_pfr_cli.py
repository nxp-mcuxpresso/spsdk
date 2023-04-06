#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `pfr` application."""
import filecmp
import logging
import os

import pytest
from click.testing import CliRunner
from ruamel.yaml import YAML

from spsdk.apps import pfr as cli
from spsdk.apps import spsdk_apps
from spsdk.pfr import CMPA
from spsdk.pfr.pfr import PfrConfiguration
from spsdk.utils.misc import load_configuration, use_working_directory


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ["--help"])
    assert help_result.exit_code == 0, help_result.output
    assert "Show this message and exit." in help_result.output


def test_cli_devices():
    """Test PFR CLI - devices."""
    runner = CliRunner()
    result = runner.invoke(cli.main, ["devices"])
    for device in CMPA.devices():
        assert device in result.stdout


def test_cli_devices_global():
    """Test PFR CLI - devices from global space."""
    runner = CliRunner()
    result = runner.invoke(spsdk_apps.main, ["pfr", "devices"])
    for device in CMPA.devices():
        assert device in result.stdout


def test_generate_cmpa(data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary."""
    cmd = f"generate-binary --output {tmpdir}/pnd.bin "
    cmd += f"--user-config {data_dir}/cmpa_96mhz.json --calc-inverse "
    cmd += f"--secret-file {data_dir}/selfsign_privatekey_rsa2048.pem "
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    new_data = open(f"{tmpdir}/pnd.bin", "rb").read()
    expected = open(f"{data_dir}/CMPA_96MHz.bin", "rb").read()
    assert new_data == expected


def test_generate_cmpa_with_elf2sb(data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary with elf2sb."""
    org_file = f"{tmpdir}/org.bin"
    new_file = f"{tmpdir}/new.bin"
    big_file = f"{tmpdir}/big.bin"

    cmd = "generate-binary --user-config cmpa_96mhz.json --calc-inverse"
    # basic usage when keys are passed on command line
    cmd1 = cmd + f" -o {org_file} -f rotk0_rsa_2048.pub -f rotk1_rsa_2048.pub"
    # elf2sb config file contains previous two keys + one empty line + 4th entry is not present
    cmd2 = cmd + f" -o {new_file} -e elf2sb_config.json"
    # keys on command line are in exclusion with elf2sb configuration, the command fails
    cmd3 = (
        cmd
        + f" -o {big_file} -e big_elf2sb_config.json -f rotk0_rsa_2048.pub -f rotk1_rsa_2048.pub"
    )
    with use_working_directory(data_dir):
        result = CliRunner().invoke(cli.main, cmd1.split())
        assert result.exit_code == 0, result.output
        result = CliRunner().invoke(cli.main, cmd2.split())
        assert result.exit_code == 0, result.output
        result = CliRunner().invoke(cli.main, cmd3.split())
        assert result.exit_code != 0, result.output
    assert filecmp.cmp(org_file, new_file)


def test_generate_cmpa_with_elf2sb_lpc55s3x(data_dir, tmpdir):
    """Test PFR CLI - Generation CMPA binary with elf2sb."""
    new = f"{tmpdir}/new.bin"
    org = "cmpa_lpc55s3x.bin"
    cmd = f"generate-binary --user-config cmpa_lpc55s3x.json -e mbi_config_lpc55s3x.json -o {new}"

    with use_working_directory(data_dir):
        result = CliRunner().invoke(cli.main, cmd.split())
        assert result.exit_code == 0, result.output
        assert filecmp.cmp(org, new)


def test_parse(data_dir, tmpdir):
    """Test PFR CLI - Parsing CMPA binary to get config."""
    cmd = "parse-binary --device lpc55s6x --type cmpa "
    cmd += f"--binary {data_dir}/CMPA_96MHz.bin "
    cmd += f"--show-diff "
    cmd += f"--output {tmpdir}/config.yml"
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    new_cfg = PfrConfiguration(f"{tmpdir}/config.yml")
    expected_cfg = PfrConfiguration(f"{data_dir}/cmpa_96mhz_rotkh.yml")
    assert new_cfg.settings == expected_cfg.settings


def test_user_config(tmpdir):
    """Test PFR CLI - Generation CMPA user config."""
    cmd = f"get-template --device lpc55s6x --type cmpa --output {tmpdir}/cmpa.yml"
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    # verify that the output is a valid json object
    pfr_config = PfrConfiguration(f"{tmpdir}/cmpa.yml")
    assert pfr_config
    assert pfr_config.type == "CMPA"
    assert pfr_config.device == "lpc55s6x"


def test_info(tmpdir):
    """Test PFR CLI - Creating HTML fields information."""
    cmd = f"info --device lpc55s6x --type cmpa --output {tmpdir}/cmpa.html"
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    assert os.path.isfile(f"{tmpdir}/cmpa.html")


@pytest.mark.parametrize(
    "test_pass,dfl_niden,dfl_inverse,force,calc_inverse",
    [
        (True, 0x0, 0xFFFF, False, False),  # OK
        (True, 0x0, 0xFFFE, False, True),  # breaking rule 1.4
        (True, 0x0, 0xFFFE, True, False),  # breaking rule 1.4
        (True, 0x1, 0xFFFE, True, False),  # breaking rule 1.7
        (False, 0x0, 0xFFFE, False, False),  # breaking rule 1.4
        (False, 0x1, 0xFFFE, False, False),  # breaking rule 1.7
        (False, 0x1, 0xFFFE, False, True),  # breaking rule 1.7
    ],
)
def test_pfrc_integration_1(
    tmp_path, data_dir, test_pass, dfl_niden, dfl_inverse, force, calc_inverse
):
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    config = load_configuration(cmpa_config_template)
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"]["NIDEN"] = dfl_niden
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"]["INVERSE_VALUE"] = dfl_inverse
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    output_bin = os.path.join(tmp_path, "pfr.bin")
    with open(cmpa_config_path, "w") as fp:
        yaml = YAML()
        yaml.dump(config, fp)

    cmd = f"generate-binary --user-config {cmpa_config_path} --output {output_bin}"
    if force:
        cmd += " --force"
    if calc_inverse:
        cmd += " --calc-inverse"
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    expected_code = 0 if test_pass else 1
    assert result.exit_code == expected_code
