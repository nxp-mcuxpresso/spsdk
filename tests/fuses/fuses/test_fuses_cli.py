#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for SPSDK NXP Fuses CLI functionality.

This module contains comprehensive test cases for the nxpfuses command-line
interface, covering fuse operations like reading, writing, and configuration
management across NXP MCU devices.
"""

import os
from typing import Any, Union
from unittest.mock import patch

import pytest

from spsdk.apps import nxpfuses
from spsdk.fuses.fuses import Fuses
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_configuration, load_file
from tests.cli_runner import CliRunner
from tests.fuses.fuses.fuses_test_operator import TestBlhostFuseOperator


def mock_fuses_operator(*args: Any, **kwargs: Any) -> TestBlhostFuseOperator:
    """Create a mock fuses operator for testing purposes.

    This function serves as a factory method to instantiate a TestBlhostFuseOperator
    with the specified family revision for use in unit tests.

    :param args: Variable length argument list (unused).
    :param kwargs: Keyword arguments containing configuration parameters.
    :raises AssertionError: If the 'family' parameter is not a FamilyRevision instance.
    :return: Configured TestBlhostFuseOperator instance for the specified family.
    """
    fam = kwargs.get("family")
    assert isinstance(fam, FamilyRevision)
    return TestBlhostFuseOperator(fam)


@pytest.mark.parametrize(
    "family",
    Fuses.get_supported_families(),
)
def test_nxpfuses_get_template(tmpdir: str, cli_runner: CliRunner, family: FamilyRevision) -> None:
    """Test nxpfuses get-template CLI command functionality.

    Verifies that the get-template command generates a valid YAML template file
    for the specified family and that the template contains the correct family name.

    :param tmpdir: Temporary directory path for test files.
    :param cli_runner: CLI runner instance for invoking commands.
    :param family: Family revision object containing the target family information.
    :raises AssertionError: If template file is not created or contains incorrect family name.
    """
    template = os.path.join(tmpdir, "template.yaml")
    cmd = f"get-template -f {family.name} --output {template}"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert os.path.isfile(template)
    assert load_configuration(template)["family"] == family.name


def test_nxpfuses_fuses_script(tmpdir: str, cli_runner: CliRunner, data_dir: str) -> None:
    """Test the nxpfuses fuses-script command functionality.

    This test verifies that the fuses-script command can generate a proper fuses programming
    script from a configuration file, and that the generated script contains the expected
    content and structure.

    :param tmpdir: Temporary directory path for output files.
    :param cli_runner: CLI runner fixture for invoking commands.
    :param data_dir: Directory path containing test data files.
    """
    fuses_script = os.path.join(tmpdir, "fuses.txt")
    cmd = f"fuses-script -c {os.path.join(data_dir, 'mimxrt798s_config_0.yaml')} -o {fuses_script}"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert os.path.isfile(fuses_script)
    fuses_script_content = load_file(fuses_script)
    assert isinstance(fuses_script_content, str)
    assert "BLHOST fuses programming script" in fuses_script_content
    assert fuses_script_content.count("efuse-program-once") == 15


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
def test_nxpfuses_fuses_write_single(cli_runner: CliRunner) -> None:
    """Test nxpfuses CLI write-single command functionality.

    This test verifies that the write-single command correctly processes arguments
    and executes the expected fuse write operation with proper parameters.

    :param cli_runner: CLI test runner fixture for invoking command line operations.
    """
    # This may eventually cause some conflicts when multiple tests run concurrently
    TestBlhostFuseOperator.ACTIONS = []
    cmd = "write-single -f mimxrt798s -n BOOT_CFG0 -v 0x5 --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS
    write_action = TestBlhostFuseOperator.ACTIONS[-1]
    assert write_action.action_type == "write"
    assert write_action.fuse_index == 0x88
    assert write_action.value == 0x5


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_write(cli_runner: CliRunner, data_dir: str) -> None:
    """Test nxpfuses CLI write command functionality.

    This test verifies that the nxpfuses write command properly processes a configuration
    file and generates the expected fuse write operations. It checks that the correct
    number of write actions are created and validates the sequence of operations.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Path to test data directory containing configuration files.
    """
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
def test_nxpfuses_fuses_print_single(
    cli_runner: CliRunner, data_dir: str, caplog: Any, name: Union[str, int]
) -> None:
    """Test printing a single fuse using the nxpfuses CLI command.

    This test verifies that the nxpfuses print command correctly handles printing
    a single fuse by name or index, validates the blhost operator actions,
    and checks the formatted output contains expected fuse information.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param caplog: Pytest fixture for capturing log output.
    :param name: Fuse name or index to print.
    """
    caplog.set_level(100_000)
    TestBlhostFuseOperator.ACTIONS = []
    cmd = f"print -f mimxrt798s -n {name}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    assert TestBlhostFuseOperator.ACTIONS[-1].action_type == "read"
    assert TestBlhostFuseOperator.ACTIONS[-1].fuse_index == 0x91
    assert "Fuse name:        XSPI0_IPED_CTX1" in result.output
    assert "Fuse OTP index:   0x91" in result.output
    assert "Fuse value:       0x00000000" in result.output
    assert "Fuse locks:       No locks" in result.output


@patch("spsdk.apps.nxpfuses.get_fuse_operator", mock_fuses_operator)
@patch("spsdk.fuses.fuses.Fuses.fuse_operator_type", TestBlhostFuseOperator)
def test_nxpfuses_fuses_get_config(
    cli_runner: CliRunner, data_dir: str, caplog: Any, tmpdir: str
) -> None:
    """Test nxpfuses CLI get-config command functionality.

    This test verifies the get-config command can generate configuration files,
    save them to specified output paths, and handle diff-only mode to show
    only modified fuse registers.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param caplog: Pytest fixture for capturing log messages.
    :param tmpdir: Temporary directory path for test file operations.
    """
    out = os.path.join(tmpdir, "config.yaml")
    cmd = f"get-config -f mimxrt798s -o {out}"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    assert "The fuses configuration has been saved" in result.output
    assert os.path.isfile(out)
    assert load_configuration(out)["family"] == "mimxrt798s"
    cmd = "write-single -f mimxrt798s -n BOOT_CFG0 -v 0x5 --yes"
    cli_runner.invoke(nxpfuses.main, cmd.split())
    cmd = f"get-config -f mimxrt798s -o {out} --diff-only"
    result = cli_runner.invoke(nxpfuses.main, cmd.split())
    cfg = load_configuration(out)
    assert len(cfg["registers"]) == 1
    assert next(iter(cfg["registers"])) == "BOOT_CFG0"
