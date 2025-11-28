#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK nxpimage FCF functionality tests.

This module contains test cases for the Flash Configuration Field (FCF)
functionality of the nxpimage application, covering CLI commands for
template generation, export, and parsing operations.
"""

import filecmp
import os
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.image.fcf.fcf import FCF
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family",
    FCF.get_supported_families(),
)
def test_nxpimage_fcf_template_cli(
    cli_runner: CliRunner, tmpdir: Any, family: FamilyRevision
) -> None:
    """Test FCF template CLI command functionality.

    Verifies that the FCF get-template command generates a valid template file
    for the specified family and saves it to the expected output location.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file output.
    :param family: Target MCU family revision for FCF template generation.
    :raises AssertionError: When the expected FCF template file is not created.
    """
    cmd = f"fcf get-template -f {family.name} --output {tmpdir}/fcf_{family.name}.yml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/fcf_{family.name}.yml")


@pytest.mark.parametrize("family", ["mcxc041", "mcxc141", "mc56f81768", "mc56f81868"])
def test_nxpimage_fcf_export_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str
) -> None:
    """Test FCF export functionality via CLI interface.

    Verifies that the FCF (Flash Configuration Field) export command works correctly
    by comparing the generated output file with the expected reference file.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Path to test data directory containing reference files.
    :param family: Target MCU family name for FCF configuration.
    """
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "fcf", family, f"fcf_{family}.yaml")
        out_file = os.path.join(tmpdir, f"fcf_{family}_exported.bin")
        cmd = ["fcf", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "fcf", family, "fcf.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family, binary",
    [
        ("mcxc041", "fcf.bin"),
        ("mcxc141", "fcf.bin"),
        ("mc56f81768", "fcf.bin"),
        ("mc56f81868", "fcf.bin"),
    ],
)
def test_nxpimage_fcf_parse_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, binary: str
) -> None:
    """Test FCF parse CLI command functionality.

    This test verifies that the FCF (Flash Configuration Field) parse command
    works correctly through the CLI interface. It executes the parse command
    with specified family and binary file, then validates that the output
    configuration file is created successfully.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for FCF parsing.
    :param binary: Name of the binary file to parse for FCF data.
    """
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "fcf", family)
        binary_path = os.path.join(data_folder, binary)
        out_config = os.path.join(tmpdir, f"fcf_{family}.yaml")
        cmd = [
            "fcf",
            "parse",
            "-f",
            family,
            "-b",
            binary_path,
            "-o",
            out_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        assert os.path.isfile(out_config)
