#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK CLI applications help functionality testing module.

This module provides comprehensive testing for help messages and command-line
interface functionality across all registered SPSDK applications. It ensures
that help text is properly displayed and accessible for all commands and
subcommands.
"""

import logging
import os
import sys
from typing import Any
from unittest.mock import patch

from spsdk import SPSDK_DATA_FOLDER
from spsdk.apps import spsdk_apps
from spsdk.apps.spsdk_apps import main as spsdk_main
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup
from spsdk.utils.misc import load_text
from tests.cli_runner import CliRunner

try:
    # ruff: noqa: F401
    import ftd2xx  # pylint: disable=unused-import
    import pyftdi  # pylint: disable=unused-import
    import pylibftdi  # pylint: disable=unused-import

    DK6_SUPPORT_INSTALLED = True
except (ImportError, OSError):
    DK6_SUPPORT_INSTALLED = False


def run_help(cli_runner: CliRunner, command_group: Any, help_option: bool) -> None:
    """Run help command test for CLI applications.

    This function tests the help functionality of CLI commands by invoking them with
    or without the --help flag and verifying that the expected help message is displayed.

    :param cli_runner: CLI test runner instance for executing commands.
    :param command_group: The CLI command group or command to test help functionality for.
    :param help_option: Flag indicating whether to use --help option or trigger help via other means.
    """
    expected_code = cli_runner.get_help_error_code(use_help_flag=help_option)

    result = cli_runner.invoke(
        command_group, ["--help"] if help_option else None, expected_code=expected_code
    )
    assert "Show this message and exit." in result.output


def test_spsdk_apps_help(cli_runner: CliRunner) -> None:
    """Test SPSDK applications help functionality.

    This test verifies that the main SPSDK applications entry point properly
    displays help information both when explicitly requested with help option
    and when called without arguments.

    :param cli_runner: Click CLI runner instance for testing command line interfaces.
    """
    run_help(cli_runner, spsdk_apps.main, help_option=True)
    run_help(cli_runner, spsdk_apps.main, help_option=False)


def test_spsdk_apps_subcommands_help_without_help_option(cli_runner: CliRunner) -> None:
    """Test SPSDK applications subcommands help functionality without help option.

    This test verifies that all SPSDK application subcommands can display help
    information when invoked without the explicit help option. It excludes certain
    utility commands and tests the help display mechanism for all other commands.

    :param cli_runner: Click CLI runner instance for testing command-line interfaces.
    """
    devscan = spsdk_apps.main.commands.pop("nxpdevscan")
    run_help(cli_runner, devscan, help_option=True)
    for name, command in spsdk_apps.main.commands.items():
        if name in ["utils", "get-families"]:
            continue
        logging.debug(f"running help for {name}")
        run_help(cli_runner, command, help_option=False)


def test_spsdk_apps_subcommands_help_with_help_option(cli_runner: CliRunner, caplog: Any) -> None:
    """Test SPSDK applications subcommands help functionality with help option.

    This test verifies that all SPSDK application commands and subcommands properly
    display help messages when invoked with the --help option. It recursively tests
    all command groups in the SPSDK applications tree structure.

    :param cli_runner: Click CLI runner for testing command line interfaces.
    :param caplog: Pytest fixture for capturing log messages during test execution.
    """
    caplog.set_level(100_000)

    def test_tree_group(group: CommandsTreeGroup) -> None:
        """Test command tree group recursively for help message functionality.

        This method recursively tests all commands and subcommands in a command tree group
        to ensure they properly display help messages. It verifies that each command shows
        the standard help exit message and handles special cases like optional DK6 support.

        :param group: The command tree group to test recursively.
        """
        for name, cmd in group.commands.items():
            cmd_args = [name, "--help"]
            with patch.object(sys, "argv", cmd_args):
                result = cli_runner.invoke(group, cmd_args)
            assert "Show this message and exit." in str(result.output), f"{str(group)} : {cmd}"
            if isinstance(cmd, CommandsTreeGroup):
                # test main "dk6prog" app, but skip subcommands is DK6 extras are not installed
                if cmd.name == "dk6prog" and not DK6_SUPPORT_INSTALLED:
                    continue
                test_tree_group(cmd)

    test_tree_group(spsdk_apps.main)


def test_apps_spec() -> None:
    """Test if all SPSDK applications are properly configured in apps.spec file.

    Validates that each SPSDK application command has corresponding entries in the
    PyInstaller apps.spec configuration file, including analyze, executable, and
    merge steps. Also verifies that version info files exist for each application.

    :raises AssertionError: When an application is missing from apps.spec or version info file doesn't exist.
    :raises FileNotFoundError: When apps.spec file or version info files cannot be found.
    """

    commands = spsdk_main.commands
    commands.pop("utils")  # remove utils group commands
    if "get-families" in commands:
        commands.pop("get-families")  # remove general get-families
    spsdk_apps_list = [name.replace("-", "_") for name in commands.keys()]

    root_path = os.path.join(SPSDK_DATA_FOLDER, "..", "..")
    apps_spec_path = os.path.join(root_path, "apps.spec")

    with open(apps_spec_path, "r") as spec_file:
        apps_spec_content = spec_file.read()

    for app_name in spsdk_apps_list:
        if app_name == "el2go_host":
            # el2go host is different
            continue
        # Check apps collection
        assert f"exe_{app_name},"
        assert f"a_{app_name}.datas,"  # cspell:disable-line
        assert f"a_{app_name}.binaries,"
        assert f"a_{app_name}.zipfiles,"
        # Check merge step
        assert f'(a_{app_name}, "{app_name}", "{app_name}")' in apps_spec_content
        # Check analyze step
        assert f'a_{app_name} = analyze(["spsdk/apps/{app_name}.py"])' in apps_spec_content
        # Check executables step
        assert (
            f'exe_{app_name} = executable(a_{app_name}, "{app_name}", "tools/pyinstaller/{app_name}_version_info.txt")'
            in apps_spec_content
        )
        assert f"exe_{app_name}," in apps_spec_content

        # Check if version info exists
        pyinstaller_version_path = os.path.join(
            root_path, "tools", "pyinstaller", f"{app_name}_version_info.txt"
        )
        assert os.path.exists(pyinstaller_version_path)

        version_text = load_text(pyinstaller_version_path)

        assert f"StringStruct(u'InternalName', u'{app_name}.exe')," in version_text
        assert f"StringStruct(u'OriginalFileName', u'{app_name}.exe')," in version_text
