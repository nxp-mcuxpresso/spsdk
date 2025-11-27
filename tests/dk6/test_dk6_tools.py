#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 tools CLI testing module.

This module contains comprehensive tests for the dk6prog command-line interface,
validating various DK6 device operations and CLI functionality.
"""

from spsdk.apps import dk6prog
from tests.cli_runner import CliRunner


def test_cli(cli_runner: CliRunner) -> None:
    """Test the dk6prog CLI interface functionality.

    Validates that the dk6prog command-line interface displays correct usage information
    both when invoked without arguments and with the --help flag.

    :param cli_runner: Click CLI test runner for executing command-line interface tests
    """
    result = cli_runner.invoke(
        dk6prog.main, expected_code=cli_runner.get_help_error_code(use_help_flag=False)
    )
    assert "Usage: dk6prog [OPTIONS] COMMAND1" in result.output
    result = cli_runner.invoke(
        dk6prog.main, ["--help"], expected_code=cli_runner.get_help_error_code(use_help_flag=True)
    )
    assert "Usage: dk6prog [OPTIONS] COMMAND1" in result.output


def test_cli_listdev(cli_runner: CliRunner) -> None:
    """Test the CLI listdev command functionality.

    Verifies that the dk6prog CLI tool correctly executes the listdev command
    with PYSERIAL backend and produces expected output containing device list.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    """
    result = cli_runner.invoke(dk6prog.main, "--backend PYSERIAL listdev")
    assert "List of available devices:" in result.output


def test_cli_erase(cli_runner: CliRunner) -> None:
    """Test the CLI erase command functionality.

    Verifies that the erase command help text is displayed correctly and contains
    the expected description about erasing memory content at a given address.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    """
    result = cli_runner.invoke(dk6prog.main, "--backend PYSERIAL erase --help")
    assert "Erase the content of memory at the given <ADDRESS>" in result.output


def test_cli_read(cli_runner: CliRunner) -> None:
    """Test the CLI read command functionality.

    Verifies that the CLI read command displays the correct help message
    when invoked with the --help flag.

    :param cli_runner: Click CLI test runner for invoking commands.
    """
    result = cli_runner.invoke(dk6prog.main, "--backend PYSERIAL read --help")
    assert "Reads the memory and writes it to the file or stdout." in result.output


def test_cli_info(cli_runner: CliRunner) -> None:
    """Test the CLI info command.

    This test verifies that the dk6prog CLI info command behaves correctly
    when invoked with the PYSERIAL backend, expecting it to exit with code 1.

    :param cli_runner: Click CLI test runner for invoking command line interfaces
    """
    cli_runner.invoke(dk6prog.main, "--backend PYSERIAL info", expected_code=1)
    # assert "Issues ISP sequence as defined in Driver interface." in result.output
