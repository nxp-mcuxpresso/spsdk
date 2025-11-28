#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for FCB functionality in nxpimage application.

This module contains comprehensive tests for the FCB (Flexspi Configuration Block)
related features of the nxpimage command-line tool, including export operations,
CLI parsing, template generation, and error handling scenarios.
"""

import filecmp
import os
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.fcb.fcb import FCB
from spsdk.image.mem_type import MemoryType
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", "flexspi_nor"),
        ("rt6xx", "flexspi_nor"),
        ("mimxrt798s", "xspi_nor"),
        ("rt105x", "flexspi_nor"),
        ("rt106x", "flexspi_nor"),
        ("rt117x", "flexspi_nor"),
        ("lpc55s3x", "flexspi_nor"),
        ("mcxn9xx", "flexspi_nor"),
    ],
)
def test_nxpimage_fcb_export(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, mem_type: str
) -> None:
    """Test FCB export functionality using CLI runner.

    This test verifies that the FCB (Flash Configuration Block) export command
    works correctly by comparing the exported binary file with the expected
    reference file.

    :param cli_runner: CLI runner instance for executing commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Path to test data directory containing reference files.
    :param family: Target MCU family name.
    :param mem_type: Memory type for FCB configuration.
    """
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "fcb", family, f"fcb_{family}_{mem_type}.yaml")
        out_file = os.path.join(tmpdir, f"fcb_{family}_exported.bin")
        cmd = ["bootable-image", "fcb", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "fcb", family, "fcb.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", "flexspi_nor"),
        (
            "rt6xx",
            "flexspi_nor",
        ),
        ("mimxrt798s", "xspi_nor"),
        ("rt105x", "flexspi_nor"),
        ("rt106x", "flexspi_nor"),
        ("rt117x", "flexspi_nor"),
        ("lpc55s3x", "flexspi_nor"),
        ("mcxn9xx", "flexspi_nor"),
    ],
)
def test_nxpimage_fcb_parse_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, mem_type: str
) -> None:
    """Test FCB parse CLI command functionality.

    This test verifies that the FCB (Flash Configuration Block) parse command
    works correctly through the CLI interface. It creates a temporary output
    file, runs the parse command with specified family and memory type parameters,
    and validates that the output configuration file is generated successfully.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Base directory containing test data files
    :param family: Target MCU family name for FCB parsing
    :param mem_type: Memory type specification for FCB configuration
    """
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "fcb", family)
        binary_path = os.path.join(data_folder, "fcb.bin")
        out_config = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        cmd = [
            "bootable-image",
            "fcb",
            "parse",
            "-f",
            family,
            "-m",
            mem_type,
            "-b",
            binary_path,
            "-o",
            out_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        assert os.path.isfile(out_config)


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("mimxrt595s", ["flexspi_nor"]),
        ("mimxrt685s", ["flexspi_nor"]),
        ("mimxrt1010", ["flexspi_nor"]),
        ("mimxrt1015", ["flexspi_nor"]),
        ("mimxrt1024", ["flexspi_nor"]),
        ("mimxrt1040", ["flexspi_nor"]),
        ("mimxrt1050", ["flexspi_nor"]),
        ("mimxrt1064", ["flexspi_nor"]),
        ("mimxrt1166", ["flexspi_nor"]),
        ("mimxrt1176", ["flexspi_nor"]),
        ("mimxrt1189", ["flexspi_nor"]),
        ("lpc55s36", ["flexspi_nor"]),
        ("rw612", ["flexspi_nor"]),
        ("mcxn947", ["flexspi_nor"]),
        ("lpc5536", ["flexspi_nor"]),
        ("mimxrt798s", ["xspi_nor"]),
    ],
)
def test_nxpimage_fcb_template_cli(
    cli_runner: CliRunner, tmpdir: Any, family: str, mem_types: list[str]
) -> None:
    """Test FCB template CLI command functionality.

    Verifies that the bootable-image fcb get-templates command correctly generates
    FCB template files for the specified family and memory types.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param family: Target MCU family name.
    :param mem_types: List of memory types to verify template generation for.
    """
    cmd = f"bootable-image fcb get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)


@pytest.mark.parametrize(
    "binary,fail",
    [
        (b"0" * 512, True),
        (b"FCFB" + b"0" * 507, True),
        (b"FCFB" + b"0" * 508, False),
        (b"FCFB" + b"0" * 512, False),
        (b"CFBF" + b"0" * 512, False),
    ],
)
@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", MemoryType.FLEXSPI_NOR),
        ("rt117x", MemoryType.FLEXSPI_NOR),
        ("mimxrt1189", MemoryType.FLEXSPI_NOR),
    ],
)
def test_fcb_parse_invalid(binary: bytes, fail: bool, family: str, mem_type: MemoryType) -> None:
    """Test FCB parsing with invalid binary data.

    This test function validates the FCB (Flash Configuration Block) parsing behavior
    when provided with potentially invalid binary data. It checks whether parsing
    should fail or succeed based on the expected outcome.

    :param binary: Binary data to be parsed as FCB.
    :param fail: Flag indicating whether parsing is expected to fail.
    :param family: Target MCU family identifier string.
    :param mem_type: Memory type specification for FCB parsing.
    :raises SPSDKError: When fail is True and parsing encounters an error (expected behavior).
    """
    if fail:
        with pytest.raises(SPSDKError):
            FCB.parse(binary, family=FamilyRevision(family), mem_type=mem_type)
    else:
        FCB.parse(binary, family=FamilyRevision(family), mem_type=mem_type)


@pytest.mark.parametrize(
    "family,mem_type,is_valid",
    [
        ("mimxrt798s", "flexspi_nor", False),
        ("mimxrt798s", "xspi_nor", True),
        ("mimxrt798s", None, True),
    ],
)
def test_default_memory_type(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, mem_type: str, is_valid: bool
) -> None:
    """Test default memory type handling in FCB parse command.

    This test verifies that the FCB parse command correctly handles different memory types
    and validates the expected behavior for both valid and invalid memory type configurations.

    :param cli_runner: CLI test runner instance for executing commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for FCB parsing.
    :param mem_type: Memory type parameter to test (empty string for default).
    :param is_valid: Expected validity of the command execution.
    """
    binary_path = os.path.join(data_dir, "fcb", family, "fcb.bin")
    cmd = f"bootable-image fcb parse -f {family} -b {binary_path} -o {tmpdir}/output.yaml"
    if mem_type:
        cmd += f" -m {mem_type}"
    cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0 if is_valid else -1)
