#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Trust provisioning CLI application functionality."""
import os
import shutil

import pytest

from spsdk.apps import tphost as cli
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


def test_tphost_cli_tp_load(cli_runner: CliRunner, data_dir, tmpdir):
    """Test of TP load CLI basic functionality."""

    dest_dir = f"{tmpdir}/data"
    # in Python 3.6 the destination folder MUST NOT exist, thus we need a subfolder
    shutil.copytree(data_dir, dest_dir)

    with use_working_directory(dest_dir):
        cli_runner.invoke(
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


def test_tphost_cli_get_template(cli_runner: CliRunner, tmpdir):
    """Test of Get Configuration template CLI basic functionality."""
    cli_runner.invoke(
        cli.main,
        ["get-template", "-f", "lpc55s6x", "-o", tmpdir + "cfg_template.yml"],
    )
    assert os.path.isfile(tmpdir + "cfg_template.yml")


def test_tphost_cli_list_tpdevs(cli_runner: CliRunner, data_dir):
    """Test of List TP devices CLI basic functionality."""
    result = cli_runner.invoke(
        cli.main,
        [
            "list-tpdevices",
            "--tp-device",
            "swmodel",
            "--tp-device-parameter",
            f"config_file={data_dir}/device_config.yaml",
        ],
    )
    assert "card1" in result.output
    assert "card2" in result.output


def test_tphost_cli_list_tptarget(cli_runner: CliRunner, data_dir):
    """Test of List TP targets CLI basic functionality."""
    result = cli_runner.invoke(
        cli.main,
        [
            "list-tptargets",
            "--tp-target",
            "swmodel",
            "--tp-target-parameter",
            f"config_file={data_dir}/target_config.yaml",
        ],
    )
    assert "lpc55s69" in result.output


def test_tphost_cli_device_help(cli_runner: CliRunner):
    """Test of get device help CLI basic functionality."""
    result = cli_runner.invoke(
        cli.main,
        ["device-help", "-d", "swmodel"],
    )
    assert "SWMODEL device" in result.output


def test_tphost_cli_target_help(cli_runner: CliRunner):
    """Test of get target help CLI basic functionality."""
    result = cli_runner.invoke(
        cli.main,
        ["target-help", "-t", "swmodel"],
    )
    assert "SWMODEL target" in result.output


def test_tphost_cli_extract(cli_runner: CliRunner, data_dir, tmpdir):
    cli_runner.invoke(
        cli.main,
        [
            "verify",
            "--audit-log",
            f"{data_dir}/tp_audit_log.db",
            "--audit-log-key",
            f"{data_dir}/oem_log_puk.pub",
            "--output",
            tmpdir,
        ],
    )
    assert len(os.listdir(tmpdir)) == 20


def test_tphost_cli_extract_skip_nxp(cli_runner: CliRunner, data_dir, tmpdir):
    cli_runner.invoke(
        cli.main,
        [
            "verify",
            "--audit-log",
            f"{data_dir}/tp_audit_log.db",
            "--audit-log-key",
            f"{data_dir}/oem_log_puk.pub",
            "--output",
            tmpdir,
            "--skip-nxp",
        ],
    )
    assert len(os.listdir(tmpdir)) == 16


@pytest.mark.parametrize(
    "family",
    [
        ("lpc55s0x"),
        ("lpc55s1x"),
        ("lpc55s2x"),
        ("lpc55s3x"),
        ("lpc55s6x"),
    ],
)
def test_tphost_cli_get_template(cli_runner: CliRunner, tmpdir, family):
    """Test for get template in shadowregs."""
    cmd = f"get-template --family {family} --output {tmpdir}/tphost.yml"
    cli_runner.invoke(cli.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/tphost.yml")
