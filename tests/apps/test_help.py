#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test that help message for all registered CLI apps works."""
import logging

from click.testing import CliRunner

from spsdk.apps import spsdk_apps


def run_help(command_group, help_option):
    runner = CliRunner()
    result = runner.invoke(command_group, ["--help"] if help_option else None)
    assert result.exit_code == 0
    assert "Show this message and exit." in result.output


def test_spsdk_apps_help():
    run_help(spsdk_apps.main, help_option=True)
    run_help(spsdk_apps.main, help_option=False)


def test_spsdk_apps_subcommands_help():
    devscan = spsdk_apps.main.commands.pop("nxpdevscan")
    run_help(devscan, help_option=True)
    for name, command in spsdk_apps.main.commands.items():
        logging.debug(f"running help for {name}")
        run_help(command, help_option=True)
        run_help(command, help_option=False)
