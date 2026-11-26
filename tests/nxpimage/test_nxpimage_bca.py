#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK nxpimage BCA functionality tests.

This module contains comprehensive test cases for the Boot Configuration Area (BCA)
functionality within the nxpimage application. Tests cover CLI operations including
template generation, export operations, and parsing capabilities for BCA components.
"""

import filecmp
import os
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.image.bca.bca import BCA
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import use_working_directory
from spsdk.utils.verifier import VerifierResult
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family",
    BCA.get_supported_families(),
)
def test_nxpimage_bca_template_cli(
    cli_runner: CliRunner, tmpdir: Any, family: FamilyRevision
) -> None:
    """Test BCA template generation CLI command.

    This test verifies that the BCA get-template command successfully generates
    a template file for the specified family and saves it to the expected location.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file output.
    :param family: Family revision specification for BCA template generation.
    """
    cmd = f"bca get-template -f {family.name} --output {tmpdir}/bca_{family.name}.yml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/bca_{family.name}.yml")


@pytest.mark.parametrize(
    "family",
    ["mcxc041", "mcxc141", "mc56f81768", "mc56f81868"],
)
def test_nxpimage_bca_export_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str
) -> None:
    """Test BCA export functionality via CLI interface.

    This test verifies that the BCA (Boot Configuration Area) export command
    works correctly through the command line interface. It uses a YAML configuration
    file to export a BCA binary and compares the output with an expected reference file.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Path to test data directory containing reference files
    :param family: MCU family name for selecting appropriate test data
    """
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "bca", family, f"bca_{family}.yaml")
        out_file = os.path.join(tmpdir, f"bca_{family}_exported.bin")
        cmd = ["bca", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "bca", family, "bca.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family, binary",
    [
        ("mcxc041", "bca.bin"),
        ("mcxc141", "bca.bin"),
        ("mc56f81768", "bca.bin"),
        ("mc56f81868", "bca.bin"),
    ],
)
def test_nxpimage_bca_parse_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, binary: str
) -> None:
    """Test CLI parsing of BCA (Boot Configuration Area) binary files.

    This test verifies that the nxpimage CLI can successfully parse a BCA binary
    file for a specific MCU family and generate a corresponding YAML configuration
    file output.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data files.
    :param family: MCU family name for BCA parsing.
    :param binary: Name of the binary file to parse.
    """
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bca", family)
        binary_path = os.path.join(data_folder, binary)
        out_config = os.path.join(tmpdir, f"bca_{family}.yaml")
        cmd = [
            "bca",
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


@pytest.mark.parametrize(
    "family",
    BCA.get_supported_families(),
)
def test_bca_verify_default(family: FamilyRevision) -> None:
    """Test BCA verifier of a default BCA succeeds without the fallback warning.

    :param family: Family revision specification for BCA.
    """
    verifier = BCA(family).verify()

    assert verifier.result == VerifierResult.SUCCEEDED
    report = verifier.draw(colorize=False)
    assert "Not implemented" not in report
    assert "BCA tag(Succeeded)" in report
    assert "BCA size(Succeeded)" in report


def test_bca_verify_mcxc141(data_dir: str) -> None:
    """Test BCA verifier reports the effective register and bitfield settings.

    :param data_dir: Path to test data directory.
    """
    config_file = os.path.join(data_dir, "bca", "mcxc141", "bca_mcxc141.yaml")
    bca = BCA.load_from_config(Config.create_from_file(config_file))

    verifier = bca.verify()

    assert verifier.result == VerifierResult.SUCCEEDED
    report = verifier.draw(colorize=False)
    assert "I2C_SLAVE_ADDRESS(Succeeded): 0xAA" in report
    assert "PERIPHERAL_DETECTION_TIMEOUT(Succeeded): 0x5555" in report
    assert "LPUART(Succeeded): DISABLE" in report


def test_bca_verify_invalid_tag() -> None:
    """Test BCA verifier reports an error for an invalid BCA tag."""
    bca = BCA(FamilyRevision("mcxc444"))
    bca.registers.find_reg("TAG").set_value(0x12345678)

    verifier = bca.verify()

    assert verifier.result == VerifierResult.ERROR
    assert "BCA tag(Error)" in verifier.draw(colorize=False)
