#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Trust provisioning CLI application functionality."""
import os
import shutil

from click.testing import CliRunner

from spsdk.apps import tphost as cli
from spsdk.utils.misc import use_working_directory


def test_tphost_cli_tp_load(data_dir, tmpdir):
    """Test of TP load CLI basic functionality."""

    dest_dir = f"{tmpdir}/data"
    # in Python 3.6 the destination folder MUST NOT exist, thus we need a subfolder
    shutil.copytree(data_dir, dest_dir)

    with use_working_directory(dest_dir):
        runner = CliRunner()
        result = runner.invoke(
            cli.main,
            [
                "load",
                "--tp-device",
                "swmodel",
                "--tp-device-parameter",
                "config_file=device_config.yaml",
                "--tp-device-parameter",
                "id=123456789",
                "--tp-target",
                "swmodel",
                "--tp-target-parameter",
                "config_file=target_config.yaml",
                "--tp-target-parameter",
                "id=com3",
                "--family",
                "lpc55s6x",
                "--audit-log",
                "audit_log.yaml",
            ],
        )
        assert result.exit_code == 0


def test_tphost_cli_get_cfg_template(tmpdir):
    """Test of Get Configuration template CLI basic functionality."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["get-cfg-template", "-o", tmpdir + "cfg_template.yml"],
    )
    assert result.exit_code == 0
    assert os.path.isfile(tmpdir + "cfg_template.yml")


def test_tphost_cli_list_tpdevs(data_dir):
    """Test of List TP devices CLI basic functionality."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "list-tpdevices",
            "--tp-device",
            "swmodel",
            "--tp-device-parameter",
            f"config_file={data_dir}/device_config.yaml",
        ],
    )
    assert result.exit_code == 0
    assert "card1" in result.output
    assert "card2" in result.output


def test_tphost_cli_list_tptarget(data_dir):
    """Test of List TP targets CLI basic functionality."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "list-tptargets",
            "--tp-target",
            "swmodel",
            "--tp-target-parameter",
            f"config_file={data_dir}/target_config.yaml",
        ],
    )
    assert result.exit_code == 0
    assert "lpc55s69" in result.output


def test_tphost_cli_device_help():
    """Test of get device help CLI basic functionality."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["device-help", "-d", "swmodel"],
    )
    assert result.exit_code == 0
    assert "SWMODEL device" in result.output


def test_tphost_cli_target_help():
    """Test of get target help CLI basic functionality."""
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        ["target-help", "-t", "swmodel"],
    )
    assert result.exit_code == 0
    assert "SWMODEL target" in result.output


def test_tphost_cli_extract(data_dir, tmpdir):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "verify",
            "--audit-log",
            f"{data_dir}/tp_audit_log.db",
            "--audit-log-key",
            f"{data_dir}/oem_log_puk.pub",
            "--destination",
            tmpdir,
        ],
    )
    assert result.exit_code == 0
    assert len(os.listdir(tmpdir)) == 20


def test_tphost_cli_extract_skip_nxp(data_dir, tmpdir):
    runner = CliRunner()
    result = runner.invoke(
        cli.main,
        [
            "verify",
            "--audit-log",
            f"{data_dir}/tp_audit_log.db",
            "--audit-log-key",
            f"{data_dir}/oem_log_puk.pub",
            "--destination",
            tmpdir,
            "--skip-nxp",
        ],
    )
    assert result.exit_code == 0
    assert len(os.listdir(tmpdir)) == 16
