#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test that help message for all registered CLI apps works."""
import logging
import sys
from unittest.mock import patch

from spsdk.apps import spsdk_apps
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup
from tests.cli_runner import CliRunner

try:
    import pyftdi
    import pylibftdi
    import ftd2xx

    DK6_SUPPORT_INSTALLED = True
except (ImportError, OSError):
    DK6_SUPPORT_INSTALLED = False


def run_help(cli_runner: CliRunner, command_group, help_option):
    result = cli_runner.invoke(command_group, ["--help"] if help_option else None)
    assert "Show this message and exit." in result.output


def test_spsdk_apps_help(cli_runner: CliRunner):
    run_help(cli_runner, spsdk_apps.main, help_option=True)
    run_help(cli_runner, spsdk_apps.main, help_option=False)


def test_spsdk_apps_subcommands_help_without_help_option(cli_runner: CliRunner):
    devscan = spsdk_apps.main.commands.pop("nxpdevscan")
    run_help(cli_runner, devscan, help_option=True)
    for name, command in spsdk_apps.main.commands.items():
        if name == "clear-cache":
            continue
        logging.debug(f"running help for {name}")
        run_help(cli_runner, command, help_option=False)


def test_spsdk_apps_subcommands_help_with_help_option(cli_runner: CliRunner, caplog):
    caplog.set_level(100_000)

    def test_tree_group(group: CommandsTreeGroup):
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
