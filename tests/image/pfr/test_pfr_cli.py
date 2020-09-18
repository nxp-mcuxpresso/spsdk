#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `pfr` application."""
import filecmp
import json
import logging
import os

from click.testing import CliRunner

from spsdk.apps import pfr as cli
from spsdk.apps import spsdk_apps
from spsdk.image import CMPA
from spsdk.utils.misc import use_working_directory

def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0, help_result.output
    assert 'Show this message and exit.' in help_result.output


def test_cli_devices():
    runner = CliRunner()
    result = runner.invoke(cli.main, ['devices'])
    for device in CMPA.devices():
        assert device in result.stdout


def test_cli_devices_global():
    runner = CliRunner()
    result = runner.invoke(spsdk_apps.main, ['pfr', 'devices'])
    for device in CMPA.devices():
        assert device in result.stdout


def test_generate_cmpa(data_dir, tmpdir):
    cmd = f'generate --output {tmpdir}/pnd.bin '
    cmd += f'--user-config {data_dir}/cmpa_96mhz.json --calc-inverse '
    cmd += f'--secret-file {data_dir}/selfsign_privatekey_rsa2048.pem '
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    new_data = open(f'{tmpdir}/pnd.bin', 'rb').read()
    expected = open(f'{data_dir}/CMPA_96MHz.bin', 'rb').read()
    assert new_data == expected


def test_generate_cmpa_with_elf2sb(data_dir, tmpdir):
    org_file = f'{tmpdir}/org.bin'
    new_file = f'{tmpdir}/new.bin'
    big_file = f'{tmpdir}/big.bin'

    cmd = 'generate --user-config cmpa_96mhz.json'
    # basic usage when keys are passed on command line
    cmd1 = cmd + f' -o {org_file} -f rotk0_rsa_2048.pub -f rotk1_rsa_2048.pub'
    # elf2sb config file contains previous two keys + one empty line + 4th entry is not preset
    cmd2 = cmd + f' -o {new_file} -e elf2sb_config.json'
    # keys on commandline take precedence and pfr ignores elf2sb configuration
    cmd3 = cmd + f' -o {big_file} -e big_elf2sb_config.json -f rotk0_rsa_2048.pub -f rotk1_rsa_2048.pub'
    with use_working_directory(data_dir):
        result = CliRunner().invoke(cli.main, cmd1.split())
        assert result.exit_code == 0, result.output
        result = CliRunner().invoke(cli.main, cmd2.split())
        assert result.exit_code == 0, result.output
        result = CliRunner().invoke(cli.main, cmd3.split())
        assert result.exit_code == 0, result.output
    assert filecmp.cmp(org_file, new_file)
    assert filecmp.cmp(org_file, big_file)


def test_parse(data_dir, tmpdir):
    cmd = 'parse --device lpc55s6x --type cmpa '
    cmd += f'--binary {data_dir}/CMPA_96MHz.bin '
    cmd += f'--show-diff '
    cmd += f'--output {tmpdir}/config.json '
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    new_data = open(f'{tmpdir}/config.json', 'r').read()
    expected = open(f'{data_dir}/cmpa_96mhz.json', 'r').read()
    assert new_data == expected


def test_user_config(data_dir, tmpdir):
    cmd = 'user-config --device lpc55s6x --type cmpa'
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    # verify that the putput is a valid json object
    assert json.loads(result.output)


def test_info(tmpdir):
    cmd = f'info --device lpc55s6x --type cmpa --output {tmpdir}/cmpa.html'
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0, result.output
    assert os.path.isfile(f'{tmpdir}/cmpa.html')
