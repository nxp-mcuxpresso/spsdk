#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Shadow Registers application test suite.

This module contains comprehensive test cases for the shadow registers command-line utility,
covering all major functionality including register operations, configuration management,
device communication, and error handling scenarios.
"""

import os
from typing import Any

import pytest

from spsdk.apps.shadowregs import main
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main(cli_runner: CliRunner) -> None:
    """Test for main menu options of the shadowregs CLI application.

    This test verifies that the main command line interface displays the help message
    correctly when invoked with the --help flag.

    :param cli_runner: Click CLI runner instance for testing command line interfaces
    :raises AssertionError: If the expected help text is not found in the output
    """
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


# This is testing none connected any probe
def test_command_line_interface_printregs_no_probe_exe(cli_runner: CliRunner) -> None:
    """Test for printregs execution menu options with no probe executable.

    Verifies that the shadowregs CLI command fails appropriately when attempting
    to print registers using a virtual interface without a proper probe setup.

    :param cli_runner: Click CLI test runner for executing command line interfaces
    """
    cmd = "-f rt5xx -i virtual printregs"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_invalid_device(cli_runner: CliRunner) -> None:
    """Test command line interface with invalid device parameter.

    Verifies that the CLI properly handles and rejects invalid device specifications
    by testing the reset command with an invalid device flag.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    """
    cmd = "-f invalid -i virtual reset"
    cli_runner.invoke(main, cmd.split(), expected_code=-1)


def test_command_line_interface_printregs_exe_fail(cli_runner: CliRunner) -> None:
    """Test for printregs execution menu options with expected failure.

    This test verifies that the printregs command fails appropriately when executed
    with virtual debug probe configuration and specific memory read expectations.

    :param cli_runner: Click CLI runner fixture for testing command line interfaces
    """
    disable_debug = "-o mem_read_exp=10"
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {disable_debug} printregs"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_printregs_exe(cli_runner: CliRunner) -> None:
    """Test for printregs execution menu options.

    This test verifies the command line interface functionality for the printregs
    command with virtual debug probe configuration and substitution parameters.

    :param cli_runner: Click CLI test runner instance for invoking commands
    """
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_printregs_r_exe(cli_runner: CliRunner) -> None:
    """Test CLI printregs command with rich output formatting.

    Verifies that the printregs command executes successfully with rich formatting
    enabled (-r flag) using a virtual debug probe and validates that register
    descriptions are included in the output.

    :param cli_runner: Click CLI test runner for invoking command line interface
    """
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs -r"
    result = cli_runner.invoke(main, cmd.split())
    assert "Register description:" in result.output


def test_command_line_interface_setreg_exe(cli_runner: CliRunner) -> None:
    """Test command line interface for setreg execution with virtual debug probe.

    This test verifies the setreg command functionality by invoking the CLI with
    a virtual debug probe configuration, setting up substitution parameters for
    specific addresses, and executing a register set operation on DCFG_CC_SOCU.

    :param cli_runner: Click CLI test runner instance for invoking commands
    """
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += " setreg -r DCFG_CC_SOCU -v 12345678"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_getreg_exe(cli_runner: CliRunner) -> None:
    """Test command line interface for getreg execution with virtual debug probe.

    This test verifies the getreg command functionality using a virtual debug probe
    with specific substitution parameters and register reading capabilities.

    :param cli_runner: Click CLI runner fixture for testing command line interfaces.
    """
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r DCFG_CC_SOCU"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_saveloadconfig_exe(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test CLI saveconfig and loadconfig command execution.

    Tests the complete workflow of saving shadow registers configuration to a file
    using the saveconfig command and then loading it back using the loadconfig command.
    The test verifies that both operations complete successfully and that the
    configuration file is properly created.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    result = cli_runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    # check if the file really exists
    assert os.path.isfile(filename)

    # Try to load the generated file
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -c {filename}"
    result = cli_runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_reset_exe(cli_runner: CliRunner) -> None:
    """Test for reset execution menu options.

    This test verifies the command line interface functionality for the reset command
    with virtual debug probe configuration, including substitution of access port
    settings and execution of the reset operation.

    :param cli_runner: Click CLI test runner instance for invoking commands
    """
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} reset"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_logger(cli_runner: CliRunner) -> None:
    """Test command line interface with logger configuration for shadowregs reset functionality.

    This test verifies the reset execution menu options by invoking the main CLI
    with virtual debug probe configuration, substitution parameters, and verbose
    logging enabled.

    :param cli_runner: Click CLI test runner for executing command line interface commands
    """
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -vv reset"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_invalid_o_param(cli_runner: CliRunner) -> None:
    """Test command line interface with invalid output parameter.

    Verifies that the shadowregs application properly handles and rejects
    invalid output parameter values, specifically testing the '-o subs_ap'
    parameter which should cause the command to fail with exit code 1.

    :param cli_runner: Click CLI test runner for executing command line interface commands
    :raises: May raise exceptions through cli_runner.invoke if command execution fails unexpectedly
    """
    enable_debug = "-o subs_ap"
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -vv reset"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_saveconfig_exe_fail(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test for saveconfig command with execution failure scenario.

    This test verifies that the saveconfig command properly handles and reports
    failures when exceptions occur during execution with virtual debug probe
    and specific substitution parameters.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_loadconfig_exe_fail(cli_runner: CliRunner, data_dir: str) -> None:
    """Test CLI loadconfig command failure with corrupted configuration.

    This test verifies that the loadconfig command properly handles and fails when
    provided with a corrupted YAML configuration file, using virtual debug probe
    with specific substitution parameters that trigger exceptions.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Directory path containing test data files.
    """
    # create path in TMP DIR
    filename = os.path.join(data_dir, "sh_regs_corrupted.yml")
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = [
        "-f",
        "rt5xx",
        "-i",
        "virtual",
        "-s",
        DebugProbeVirtual.UNIQUE_SERIAL,
        enable_debug,
        "loadconfig",
        "-c",
        filename,
    ]
    cli_runner.invoke(main, cmd, expected_code=1)


def test_command_line_interface_printregs_exe_fail1(cli_runner: CliRunner) -> None:
    """Test for printregs execution menu options with failure scenario.

    This test verifies that the printregs command fails appropriately when provided
    with debug options that include exceptions in the substitution parameters.
    The test uses a virtual debug probe with RT5xx family configuration and expects
    the command to exit with error code 1.

    :param cli_runner: Click CLI runner fixture for testing command line interfaces
    """
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_setreg_exe_fail(cli_runner: CliRunner) -> None:
    """Test command line interface setreg execution with failure scenario.

    This test verifies that the setreg command fails appropriately when attempting to set
    a register value with debug probe exceptions configured. It uses a virtual debug probe
    with specific substitution parameters that simulate exceptions during register access.

    :param cli_runner: Click CLI runner fixture for testing command line interfaces
    :raises: May raise various exceptions through the CLI invocation, expected to fail with code 1
    """
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += " setreg -r CUST_WR_RD_LOCK0 -v 12345678"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_getreg_exe_fail(cli_runner: CliRunner) -> None:
    """Test CLI getreg command execution failure scenario.

    This test verifies that the getreg command fails appropriately when executed
    with virtual debug probe configuration that includes exception scenarios in
    both substitution access points and memory locations.

    :param cli_runner: Click CLI test runner for invoking command line interface
    """
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r CUST_WR_RD_LOCK0"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_fuse_script_exe(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test command line interface for fuse script execution functionality.

    This test verifies the complete workflow of saving shadow registers configuration
    and generating BLHOST script files through the CLI interface. It tests both
    the saveconfig command with virtual debug probe and the fuses-script command
    for script generation.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory fixture for test file operations
    """
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    cli_runner.invoke(main, cmd.split())
    # check if the file really exists
    assert os.path.isfile(filename)

    # Try create BLHOST script
    script_file = os.path.join(tmpdir, "blhost_script.bsf")
    cmd = f"-f rt5xx fuses-script -c {filename} -o {script_file}"
    cli_runner.invoke(main, cmd.split())
    # check if the file really exists
    assert os.path.isfile(script_file)


@pytest.mark.parametrize(
    "family",
    [
        ("rt5xx"),
        ("rt6xx"),
        ("rw61x"),
    ],
)
def test_command_line_get_template(cli_runner: CliRunner, tmpdir: Any, family: str) -> None:
    """Test shadowregs CLI command for generating configuration template.

    Verifies that the get-template command creates a valid YAML configuration file
    for the specified MCU family in the shadowregs application.

    :param cli_runner: Click CLI test runner for executing commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param family: Target MCU family name for template generation.
    """
    cmd = f"--family {family} get-template --output {tmpdir}/shadowregs.yml"
    cli_runner.invoke(main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/shadowregs.yml")
