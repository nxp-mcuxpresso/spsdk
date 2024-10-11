#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test that help message for all registered CLI apps works."""
import logging

from spsdk import __version__ as spsdk_version
from spsdk.apps import spsdk_apps
from tests.cli_runner import CliRunner


def run_version(cli_runner: CliRunner, command_group):
    result = cli_runner.invoke(command_group, ["--version"])
    assert spsdk_version in result.output


def test_spsdk_apps_help(cli_runner: CliRunner):
    run_version(cli_runner, spsdk_apps.main)


def test_spsdk_apps_subcommands_help(cli_runner: CliRunner):
    for name, command in spsdk_apps.main.commands.items():
        if name in ["utils", "get-families"]:
            continue
        logging.debug(f"running help for {name}")
        run_version(cli_runner, command)
