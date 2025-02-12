#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test that help message for all registered CLI apps works."""
import logging
import os
import sys
from unittest.mock import patch

from spsdk.apps import spsdk_apps
from spsdk.apps.utils.common_cli_options import CommandsTreeGroup
from spsdk.utils.misc import load_text
from tests.cli_runner import CliRunner
from spsdk import SPSDK_DATA_FOLDER
from spsdk.apps.spsdk_apps import main as spsdk_main

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
        if name in ["utils", "get-families"]:
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


def test_apps_spec():
    """Test if all applications are in apps.spec."""

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
        assert f"a_{app_name}.datas,"
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
