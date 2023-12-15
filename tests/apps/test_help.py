#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test that help message for all registered CLI apps works."""
import logging

from spsdk.apps import spsdk_apps
from tests.cli_runner import CliRunner


def run_help(cli_runner: CliRunner, command_group, help_option):
    result = cli_runner.invoke(command_group, ["--help"] if help_option else None)
    assert "Show this message and exit." in result.output


def test_spsdk_apps_help(cli_runner: CliRunner):
    run_help(cli_runner, spsdk_apps.main, help_option=True)
    run_help(cli_runner, spsdk_apps.main, help_option=False)


def test_spsdk_apps_subcommands_help(cli_runner: CliRunner):
    devscan = spsdk_apps.main.commands.pop("nxpdevscan")
    run_help(cli_runner, devscan, help_option=True)
    for name, command in spsdk_apps.main.commands.items():
        logging.debug(f"running help for {name}")
        run_help(cli_runner, command, help_option=True)
        run_help(cli_runner, command, help_option=False)
