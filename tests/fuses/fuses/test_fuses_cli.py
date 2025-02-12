#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
from unittest.mock import patch

import pytest
from spsdk.utils.misc import load_configuration, load_file
from tests.cli_runner import CliRunner
from spsdk.apps import nxpfuses
from spsdk.fuses.fuses import Fuses
from tests.fuses.fuses.fuses_test_operator import TestBlhostFuseOperator


def mock_fuses_operator(*args, **kwargs):
    return TestBlhostFuseOperator()


@pytest.mark.parametrize(
    "family",
    Fuses.get_supported_families(),
)
def test_nxpfuses_get_template(tmpdir: str, cli_runner: CliRunner, family: str):
    template = os.path.join(tmpdir, "template.yaml")
    cmd = f"get-template -f {family} --output {template}"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert os.path.isfile(template)
    assert load_configuration(template)["family"] == family


def test_nxpfuses_fuses_script(tmpdir: str, cli_runner: CliRunner, data_dir: str):
    fuses_script = os.path.join(tmpdir, "fuses.txt")
    cmd = f"fuses-script -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')} -o {fuses_script}"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert os.path.isfile(fuses_script)
    fuses_script = load_file(fuses_script)
    assert "BLHOST fuses programming script" in fuses_script
    assert fuses_script.count("efuse-program-once") == 15


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
def test_nxpfuses_fuses_write_single(cli_runner: CliRunner):
    # This may eventually cause some conflicts when multiple tests run concurrently
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"write-single -f mimxrt798s -n XSPI0_IPED_CTX0 -v 0x5 --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS
    write_action = TestBlhostFuseOperator.ACTIONS[-1]
    assert write_action.action_type == "write"
    assert write_action.fuse_index == 0x90
    assert write_action.value == 0x5


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_write(cli_runner: CliRunner, data_dir):
    # This may eventually cause some conflicts when multiple tests run concurrently
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"write -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')} --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS
    write_actions = [fuse for fuse in TestBlhostFuseOperator.ACTIONS if fuse.action_type == "write"]
    assert len(write_actions) == 15  # 12x RKTH + 2x XSPI0_IPED_CTX +1x LOCK_CFG0
    assert write_actions[-1].fuse_index == 0  # Last fuse is always lock fuse


@pytest.mark.parametrize(
    "name",
    ["XSPI0_IPED_CTX1", 0x91, "fuse145"],
)
@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_print_single(cli_runner: CliRunner, data_dir, caplog, name):
    caplog.set_level(100_000)
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"print -f mimxrt798s -n {name}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS[-1].action_type == "read"
    assert TestBlhostFuseOperator.ACTIONS[-1].fuse_index == 0x91
    assert f"Fuse name:        XSPI0_IPED_CTX1" in result.output
    assert f"Fuse OTP index:   0x91" in result.output
    assert f"Fuse value:       0x00000000" in result.output
    assert f"Fuse locks:       No locks" in result.output


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_get_config(cli_runner: CliRunner, data_dir, caplog, tmpdir):
    out = os.path.join(tmpdir, "config.yaml")
    cmd = f"get-config -f mimxrt798s -o {out}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    assert "The fuses configuration has been saved" in result.output
    assert os.path.isfile(out)
    assert load_configuration(out)["family"] == "mimxrt798s"
    cmd = f"write-single -f mimxrt798s -n XSPI0_IPED_CTX0 -v 0x5 --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    cmd = f"get-config -f mimxrt798s -o {out} --diff-only"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    cfg = load_configuration(out)
    assert len(cfg["registers"]) == 1
    assert "XSPI0_IPED_CTX0" in cfg["registers"].keys()
