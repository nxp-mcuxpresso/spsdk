#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK IFR application test suite.

This module contains comprehensive tests for the IFR (Internal Flash Resident)
application functionality, verifying configuration handling, data processing,
and round-trip operations for ROM configurations and CMAC tables.
"""

import filecmp
import os
from typing import Any

import pytest

from spsdk.apps import pfr
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family, type",
    [
        ("kw45xx", "ROMCFG"),
        ("kw45xx", "CMACTable"),
        ("k32w1xx", "ROMCFG"),
        ("k32w1xx", "CMACTable"),
    ],
)
def test_ifr_user_config(cli_runner: CliRunner, tmpdir: Any, family: str, type: str) -> None:
    """Test IFR CLI user configuration template generation.

    This test verifies that the IFR CLI can successfully generate a user configuration
    template file for a specified family and type, and that the output file is created
    at the expected location.

    :param cli_runner: Click CLI test runner for invoking CLI commands
    :param tmpdir: Temporary directory fixture for test file operations
    :param family: Target MCU family name for configuration template
    :param type: Configuration type to generate template for
    :raises AssertionError: When the expected configuration file is not created
    """
    cmd = ["get-template", "-f", family, "--type", type, "--output", f"{tmpdir}/ifr.yml"]
    cli_runner.invoke(pfr.main, cmd)
    assert os.path.isfile(f"{tmpdir}/ifr.yml")


def test_roundtrip_romcfg(cli_runner: CliRunner, data_dir: str, tmpdir: Any) -> None:
    """Test roundtrip functionality for ROM configuration parsing and generation.

    This test verifies that a ROM configuration binary file can be parsed into YAML format
    and then regenerated back to binary format, with the final binary being identical
    to the original input file.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory for storing intermediate and output files.
    """
    parse_cmd = [
        "parse",
        "-f",
        "kw45xx",
        "--type",
        "romcfg",
        "--binary",
        f"{data_dir}/ref.bin",
        "--output",
        f"{tmpdir}/ref.yaml",
    ]
    cli_runner.invoke(pfr.main, parse_cmd)

    generate_cmd = f"export --config {tmpdir}/ref.yaml --output {tmpdir}/new.bin"
    cli_runner.invoke(pfr.main, generate_cmd.split())

    assert filecmp.cmp(f"{data_dir}/ref.bin", f"{tmpdir}/new.bin")


def test_roundtrip_cmac_table(cli_runner: CliRunner, data_dir: str, tmpdir: Any) -> None:
    """Test roundtrip functionality for CMAC table parsing and generation.

    This test verifies that a CMAC table binary file can be parsed into YAML format
    and then regenerated back to binary format without data loss. The test uses
    the KW45xx family configuration and compares the original and regenerated files.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory for output files during testing.
    """
    parse_cmd = [
        "parse",
        "-f",
        "kw45xx",
        "--type",
        "CMACTable",
        "--binary",
        f"{data_dir}/kw45cmac.bin",
        "--output",
        f"{tmpdir}/ref.yaml",
    ]
    cli_runner.invoke(pfr.main, parse_cmd)

    generate_cmd = f"export --config {tmpdir}/ref.yaml --output {tmpdir}/new.bin"
    cli_runner.invoke(pfr.main, generate_cmd.split())

    assert filecmp.cmp(f"{data_dir}/kw45cmac.bin", f"{tmpdir}/new.bin")
