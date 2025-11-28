#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK NXP SHE CLI application tests.

This module contains unit tests for the NXP SHE (Secure Hardware Extension)
command-line interface application, verifying CLI commands and functionality.
"""

import filecmp
import os

from spsdk.apps import nxpshe
from spsdk.utils.misc import load_secret
from tests.cli_runner import CliRunner


def test_update(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test the update command of the NXP SHE CLI tool.

    This test verifies that the update command correctly processes a configuration file
    and generates the expected binary output file by comparing it with a reference file.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    """
    config = f"{data_dir}/config.yaml"
    output = f"{tmpdir}/output.bin"
    reference = f"{data_dir}/messages.bin"

    result = cli_runner.invoke(nxpshe.main, ["update", "-c", config, "-o", output])
    assert result.exit_code == 0
    assert os.path.isfile(output)
    assert filecmp.cmp(reference, output)


def test_get_template(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test the get-template CLI command functionality.

    Verifies that the get-template command successfully generates a YAML template
    file for the specified MCU family and saves it to the designated output path.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test file output.
    """
    output = f"{tmpdir}/she_template.yaml"
    result = cli_runner.invoke(nxpshe.main, ["get-template", "-f", "mcxe247", "-o", output])
    assert result.exit_code == 0
    assert os.path.isfile(output)


def test_boot_mac(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test boot MAC calculation CLI command functionality.

    Verifies that the calc-boot-mac CLI command correctly processes input files
    and generates the expected boot MAC output file by comparing with reference data.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test input and reference files.
    :param tmpdir: Temporary directory path for output file generation.
    :raises AssertionError: If command fails, output file is not created, or content doesn't match reference.
    """
    boot_mac_key = f"{data_dir}/boot_mac_key.txt"
    data = f"{data_dir}/data.bin"
    output = f"{tmpdir}/boot_mac.txt"
    result = cli_runner.invoke(
        nxpshe.main, ["calc-boot-mac", "-k", boot_mac_key, "-d", data, "-o", output]
    )
    assert result.exit_code == 0
    assert os.path.isfile(output)
    assert filecmp.cmp(output, f"{data_dir}/boot_mac.txt")


def test_derive_key(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test derive-key CLI command functionality.

    Verifies that the derive-key command correctly derives a MAC key from a master key
    and outputs it to the specified file. Tests case-insensitive key type handling
    by using mixed case 'maC' instead of 'MAC'.

    :param cli_runner: Click CLI test runner for invoking commands
    :param data_dir: Directory path containing test data files
    :param tmpdir: Temporary directory path for output files
    """
    master_key = f"{data_dir}/master_key.txt"
    output = f"{tmpdir}/mac_key.txt"
    exp_mac_key = load_secret(f"{data_dir}/mac_key.txt")

    result = cli_runner.invoke(
        # the word MAC is capitalized weirdly on purpose, to check case-insensitivity
        nxpshe.main,
        ["derive-key", "-k", master_key, "-t", "maC", "-o", output],
    )
    assert result.exit_code == 0
    assert os.path.isfile(output)
    mac_key = load_secret(output)
    assert mac_key == exp_mac_key, "Derived key does not match expected key"
