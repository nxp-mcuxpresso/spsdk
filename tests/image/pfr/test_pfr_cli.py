#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `pfr` application."""
import json
import logging
import os

from click.testing import CliRunner

from spsdk.apps import pfr as cli
from spsdk.apps import spsdk_apps
from spsdk.image import CMPA


def test_command_line_interface():
    """Test the CLI."""
    runner = CliRunner()
    help_result = runner.invoke(cli.main, ['--help'])
    assert help_result.exit_code == 0
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
    cmd = 'generate --device lpc55xx --type cmpa '
    cmd += f'--output {tmpdir}/pnd.bin '
    cmd += f'--user-config {data_dir}/cmpa_96mhz.json --calc-inverse '
    cmd += f'--secret-type priv-key '
    cmd += f'--secure-file {data_dir}/selfsign_privatekey_rsa2048.pem '
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0
    new_data = open(f'{tmpdir}/pnd.bin', 'rb').read()
    expected = open(f'{data_dir}/CMPA_96MHz.bin', 'rb').read()
    assert new_data == expected


def test_parse(data_dir, tmpdir):
    cmd = 'parse --device lpc55xx --type cmpa '
    cmd += f'--binary {data_dir}/CMPA_96MHz.bin '
    cmd += f'--show-diff '
    cmd += f'--output {tmpdir}/config.json '
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0
    new_data = open(f'{tmpdir}/config.json', 'r').read()
    expected = open(f'{data_dir}/cmpa_96mhz.json', 'r').read()
    assert new_data == expected


def test_user_config(data_dir, tmpdir):
    cmd = 'user-config --device lpc55xx --type cmpa'
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0
    # verify that the putput is a valid json object
    assert json.loads(result.output)


def test_info(tmpdir):
    cmd = f'info --device lpc55xx --type cmpa --output {tmpdir}/cmpa.html'
    logging.debug(cmd)
    runner = CliRunner()
    result = runner.invoke(cli.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(f'{tmpdir}/cmpa.html')
