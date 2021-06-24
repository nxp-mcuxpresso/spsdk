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


def run_help(command_group):
    runner = CliRunner()
    result = runner.invoke(command_group, ["--help"])
    assert result.exit_code == 0
    assert "Show this message and exit." in result.output


def test_spsdk_apps_help():
    run_help(spsdk_apps.main)


def test_spsdk_apps_subcommands_help():
    for name, command in spsdk_apps.main.commands.items():
        logging.debug(f"running help for {name}")
        run_help(command)
