#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python(tmpdir
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for BEE (Bus Encryption Engine) functionality in nxpimage application.

This module contains comprehensive tests for the BEE encryption features
of the nxpimage tool, including basic encryption, region overlap handling,
template generation, and multiple region configurations.
"""

import os
import shutil
from typing import Any, Optional

import pytest

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner

INPUT_BINARY = "evkbimxrt1050_iled_blinky_ext_FLASH_unencrypted_nopadding.bin"


@pytest.mark.parametrize(
    "case, config, reference, engines",
    [
        (
            "both_engines_ctr",
            "bee_config.yaml",
            "evkbimxrt1050_iled_blinky_ext_FLASH_bootable_nopadding.bin",
            [0, 1],
        ),
        ("both_engines_generated_header", "bee_config.yaml", None, [0, 1]),
        ("one_engine_generated_header", "bee_config.yaml", None, [0]),
        ("both_engines_multiple_blobs", "bee_config.yaml", None, [0, 1]),
    ],
)
def test_nxpimage_bee(
    cli_runner: CliRunner,
    tmpdir: Any,
    data_dir: str,
    case: str,
    config: str,
    reference: Optional[str],
    engines: list[int],
) -> None:
    """Test NXP image BEE encryption functionality.

    This test verifies the BEE (Bus Encryption Engine) export command by:
    1. Setting up a temporary working directory with test data
    2. Running the nxpimage BEE export command with specified configuration
    3. Validating that encrypted binary and engine header files are generated
    4. Comparing output with reference file if provided

    :param cli_runner: Click CLI test runner for command execution
    :param tmpdir: Temporary directory for test files
    :param data_dir: Path to test data directory
    :param case: Test case name identifying the specific BEE scenario
    :param config: Configuration file name for BEE export
    :param reference: Optional reference file path for output validation
    :param engines: List of BEE engine numbers to validate header file generation
    """
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"bee export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(out_dir, "encrypted.bin"))
        for engine in engines:
            assert os.path.isfile(os.path.join(out_dir, f"bee_ehdr{engine}.bin"))
        if reference:
            encrypted_image_enc = load_binary(reference)
            encrypted_nxpimage = load_binary(os.path.join(out_dir, "encrypted.bin"))
            assert encrypted_image_enc == encrypted_nxpimage


@pytest.mark.parametrize(
    "case, config",
    [
        ("both_engines_generated_header_overlap", "bee_config.yaml"),
    ],
)
def test_nxpimage_bee_overlap(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, case: str, config: str
) -> None:
    """Test BEE image creation with overlapping memory regions.

    This test verifies that the nxpimage BEE export command properly handles
    and rejects configurations with overlapping memory regions by expecting
    a failure exit code.

    :param cli_runner: Click CLI test runner for command execution.
    :param tmpdir: Temporary directory for test files.
    :param data_dir: Base directory containing test data files.
    :param case: Specific test case name for BEE configuration.
    :param config: Configuration file name for BEE export command.
    """
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        cmd = f"bee export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=-1)


@pytest.mark.parametrize(
    "family",
    [
        ("rt1015"),
        ("rt102x"),
        ("rt105x"),
        ("rt106x"),
    ],
)
def test_nxpimage_bee_template_cli(cli_runner: CliRunner, tmpdir: Any, family: str) -> None:
    """Test CLI command for generating BEE template files.

    This test verifies that the 'bee get-template' CLI command successfully
    generates a template YAML file for the specified MCU family.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param family: Target MCU family name for template generation.
    """
    template = os.path.join(tmpdir, "bee_template.yaml")
    cmd = f"bee get-template -f {family} -o {template}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(template)


@pytest.mark.parametrize(
    "case, config",
    [
        ("both_engines_multiple_blobs_overlap", "bee_config.yaml"),
    ],
)
def test_nxpimage_bee_multiple(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, case: str, config: str
) -> None:
    """Test BEE functionality with multiple configuration scenarios.

    This test function validates the BEE (Bus Encryption Engine) export command
    with various configuration files and test cases. It sets up a temporary
    working directory, copies necessary test data, and executes the BEE export
    command expecting it to fail with exit code -1.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for test execution
    :param data_dir: Path to test data directory containing BEE test files
    :param case: Specific test case name to execute
    :param config: Configuration file name to use for the test
    :raises SPSDKError: When BEE export command fails unexpectedly
    """
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        cmd = f"bee export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=-1)
