#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test that help message for all registered CLI apps works."""
import logging

from click.testing import CliRunner

from spsdk import __version__ as spsdk_version
from spsdk.apps import spsdk_apps


def run_version(command_group):
    runner = CliRunner()
    result = runner.invoke(command_group, ["--version"])
    assert result.exit_code == 0
    assert spsdk_version in result.output


def test_spsdk_apps_help():
    run_version(spsdk_apps.main)


def test_spsdk_apps_subcommands_help():
    for name, command in spsdk_apps.main.commands.items():
        logging.debug(f"running help for {name}")
        run_version(command)
