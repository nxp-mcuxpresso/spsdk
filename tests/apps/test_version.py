#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK version command test suite.

This module contains test cases for validating the SPSDK version command
functionality and help message generation across all registered CLI applications.
"""

import logging
from typing import Any

from spsdk import __version__ as spsdk_version
from spsdk.apps import spsdk_apps
from tests.cli_runner import CliRunner


def run_version(cli_runner: CliRunner, command_group: Any) -> None:
    """Test version command functionality using CLI runner.

    Invokes the version command on the provided command group and verifies
    that the SPSDK version string is present in the command output.

    :param cli_runner: Click CLI runner instance for testing command execution.
    :param command_group: Command group object to test version command on.
    :raises AssertionError: When SPSDK version is not found in command output.
    """
    result = cli_runner.invoke(command_group, ["--version"])
    assert spsdk_version in result.output


def test_spsdk_apps_help(cli_runner: CliRunner) -> None:
    """Test SPSDK applications help functionality.

    This test verifies that the help command works correctly for SPSDK applications
    by running the version test with the main SPSDK apps entry point.

    :param cli_runner: Click CLI runner instance for testing command-line interfaces.
    """
    run_version(cli_runner, spsdk_apps.main)


def test_spsdk_apps_subcommands_help(cli_runner: CliRunner) -> None:
    """Test SPSDK applications subcommands help functionality.

    This test iterates through all available SPSDK application commands and verifies
    that the help functionality works correctly for each subcommand, excluding
    utility commands and get-families command.

    :param cli_runner: Click CLI runner instance for testing command line interfaces.
    """
    for name, command in spsdk_apps.main.commands.items():
        if name in ["utils", "get-families"]:
            continue
        logging.debug(f"running help for {name}")
        run_version(cli_runner, command)
