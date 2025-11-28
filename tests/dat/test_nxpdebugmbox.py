#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for SPSDK nxpdebugmbox utility application.

This module contains comprehensive test cases for the nxpdebugmbox command-line
utility, covering debug mailbox operations, probe handling, device modes,
and debug credential generation across NXP MCU portfolio.
"""

import filecmp
import os
from typing import Any, Optional

import pytest

from spsdk.apps.nxpdebugmbox import main
from spsdk.utils.family import get_device, get_families
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main(cli_runner: CliRunner) -> None:
    """Test for main menu options of the command line interface.

    This test verifies that the main CLI command displays the help message
    correctly when invoked with the --help flag.

    :param cli_runner: Click CLI test runner for invoking command line interfaces
    """
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


def get_all_devices_and_revision(
    feature: str, sub_feature: Optional[str] = None, append_latest: bool = True
) -> list[tuple[str, str]]:
    """Get list of tuples with complete device list with all revisions.

    The method retrieves all device families for the specified feature and sub_feature,
    then collects all available revisions for each device family.

    :param feature: Name of feature to get devices for.
    :param sub_feature: Name of sub_feature to filter devices, defaults to None.
    :param append_latest: Add also latest revision to the list, defaults to True.
    :return: List of tuples containing device family name and revision pairs.
    """
    ret = []
    families = get_families(feature, sub_feature)
    for family in families:
        device = get_device(family)
        for rev in device.revisions.revision_names(append_latest=append_latest):
            ret.append((family.name, rev))
    return ret


def test_nxpdebugmbox_invalid_probe_user_param(cli_runner: CliRunner) -> None:
    """Test for invalid debug probe user parameters.

    Verifies that the CLI properly handles and rejects invalid user parameters
    when configuring debug probe settings with virtual probe interface.

    :param cli_runner: Click CLI test runner for executing command line interface commands
    :raises AssertionError: If the command doesn't exit with expected error code 1
    """
    cmd = f"-o user_par -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv cmd -f lpc55s69 start"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_nxpdebugmbox_invalid_probe(cli_runner: CliRunner) -> None:
    """Test for invalid debug probe functionality.

    Verifies that the CLI properly handles and reports errors when an invalid
    debug probe is specified in the command arguments.

    :param cli_runner: Click CLI test runner instance for executing commands.
    """
    cmd = "-i virtual -vv cmd -f lpc55s69 start"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_nxpdebugmbox_valid_probe_user_param(cli_runner: CliRunner) -> None:
    """Test for valid debug probe user parameters.

    Verifies that the nxpdebugmbox CLI correctly handles valid user parameters
    when connecting to a virtual debug probe and executing start command.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    """
    cmd = f"-o user_par=1 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv cmd -f lpc55s69 start"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_start_exe(cli_runner: CliRunner) -> None:
    """Test for start command of nxp debug mailbox.

    This test verifies that the start command executes properly with virtual debug probe
    configuration for LPC55S69 target device.

    :param cli_runner: Click CLI runner fixture for testing command line interface.
    """
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv cmd -f lpc55s69 start"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_exit_exe(cli_runner: CliRunner) -> None:
    """Test for exit command of nxp debug mailbox.

    This test verifies that the exit command works correctly with the NXP debug
    mailbox using a virtual debug probe interface.

    :param cli_runner: Click CLI runner instance for testing command line interface.
    """
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv cmd -f lpc55s69 exit"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_ispmode_exe(cli_runner: CliRunner) -> None:
    """Test for ispmode command of nxp debug mailbox.

    This test verifies the ispmode command functionality by invoking it with
    virtual debug probe configuration, testing both with and without mode parameter.

    :param cli_runner: CLI runner fixture for testing command line interface.
    """
    hw_responses = '-o subs_ap={"33554440":[107941,0]}'
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {hw_responses} -vv cmd -f lpc55s69 ispmode -m 0"
    cli_runner.invoke(main, cmd.split())
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {hw_responses} -vv cmd -f lpc55s69 ispmode"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_famode_exe(cli_runner: CliRunner) -> None:
    """Test for famode command of nxp debug mailbox.

    This test verifies the functionality of the famode command in the NXP debug
    mailbox CLI interface using a virtual debug probe connection.

    :param cli_runner: Click CLI test runner instance for invoking commands.
    """
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv cmd -f lpc55s69 famode"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_erase_exe(cli_runner: CliRunner) -> None:
    """Test for erase command of nxp debug mailbox.

    This test verifies that the erase command executes properly through the CLI
    interface using a virtual debug probe with verbose output enabled.

    :param cli_runner: Click CLI runner instance for testing command execution.
    """
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv cmd -f lpc55s69 erase"
    cli_runner.invoke(main, cmd.split())


def test_generate_rsa_dc_file(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test generate debug credential file with RSA 2048 protocol.

    This test verifies the functionality of exporting a debug credential file
    using RSA 2048 encryption through the DAT CLI command. It creates a new
    debug credential file and validates that the output file is successfully generated.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory fixture for test file operations
    :param data_dir: Directory path containing test data files
    """
    out_file = f"{tmpdir}/dc_2048.cert"
    cmd = f"dat dc export -c new_dck_rsa2048.yml -o {out_file}"

    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


def test_generate_ecc_dc_file(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test generate debug credential file with ECC protocol.

    This test verifies that the DAT (Debug Authentication Tool) can successfully
    export a debug credential file using ECC (Elliptic Curve Cryptography) protocol
    with secp256r1 curve configuration.

    :param cli_runner: Click CLI test runner for invoking command line interface
    :param tmpdir: Temporary directory fixture for test file operations
    :param data_dir: Directory path containing test data files including configuration
    """
    out_file = f"{tmpdir}/dc_secp256r1.cert"
    cmd = f"dat dc export -c new_dck_secp256.yml -o {out_file}"

    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


def test_generate_dc_file_lpc55s3x_256(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test generate DC file with ECC protocol for LPC55S3x.

    This test verifies the generation of a Debug Credential (DC) file using the ECC
    secp256r1 protocol for the LPC55S3x microcontroller. It uses the DAT CLI tool
    to export a DC file based on a configuration file and validates that the output
    file is created successfully.

    :param cli_runner: CLI test runner for invoking command-line operations
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data and configuration files
    """
    out_file = f"{tmpdir}/dc_secp256r1_lpc55s3x.cert"
    cmd = f"dat dc export -c new_dck_secp256_lpc55s3x.yml -o {out_file}"
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


def test_generate_dc_file_mx95_a1(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test generation of debug credential file with ECC protocol for MX95 A0/A1 revision.

    This test verifies that the DAT (Debug Authentication Tool) can successfully
    export a debug credential file using ECC secp256r1 protocol configuration
    specifically for MX95 A0/A1 chip revisions.

    :param cli_runner: Click CLI test runner for invoking command line interface
    :param tmpdir: Temporary directory fixture for test file operations
    :param data_dir: Directory path containing test data and configuration files
    :raises AssertionError: If the generated debug credential file is not created
    """
    out_file = f"{tmpdir}/dc_secp256r1_mx95.cert"
    cmd = f"dat dc export -c dc_mx95_a1.yaml -o {out_file}"
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


def test_generate_dc_file_lpc55s3x_384(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test generate DC file with ECC protocol for LPC55S3x.

    This test verifies the generation of a Debug Credential (DC) file using
    the secp384r1 ECC curve for the LPC55S3x microcontroller. It exports
    the DC file using a YAML configuration and validates that the output
    file is created successfully.

    :param cli_runner: CLI test runner for invoking SPSDK commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data and configuration files.
    """
    out_file = f"{tmpdir}/dc_secp384r1_lpc55s3x.cert"
    cmd = f"dat dc export -c new_dck_secp384_lpc55s3x.yml -o {out_file}"
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


@pytest.mark.parametrize(
    "config",
    ["elf2sb_config.yaml", "elf2sb_config_sp.yaml"],
)
def test_generate_rsa_with_elf2sb(tmpdir: Any, data_dir: str, config: str) -> None:
    """Test RSA key generation with elf2sb configuration integration.

    This test verifies that the DAT (Debug Authentication Tool) can generate
    identical debug credential files when RSA keys are provided through an
    elf2sb configuration file instead of being embedded in the YAML configuration.
    The test compares outputs from two different approaches to ensure consistency.

    :param tmpdir: Temporary directory for test file operations
    :param data_dir: Directory containing test data files and configurations
    :param config: Path to the elf2sb configuration file containing RSA keys
    :raises AssertionError: When CLI commands fail or generated files don't match
    """
    org_file = f"{tmpdir}/org.dc"
    new_file = f"{tmpdir}/new.dc"

    cmd1 = f"dat dc export -c org_dck_rsa_2048.yml -o {org_file}"
    # keys were removed from yaml and supplied by elf2sb config
    cmd2 = f"dat dc export -c no_key_dck_rsa_2048.yml -e {config} -o {new_file}"
    with use_working_directory(data_dir):
        result = CliRunner().invoke(main, cmd1.split())
        assert result.exit_code == 0, str(result.exception)
        result = CliRunner().invoke(main, cmd2.split())
        assert result.exit_code == 0, str(result.exception)
    assert filecmp.cmp(org_file, new_file)


@pytest.mark.parametrize(
    "family, revision",
    get_all_devices_and_revision("dat"),
)
def test_nxpdebugmbox_get_template(
    cli_runner: CliRunner, tmpdir: Any, family: str, revision: str
) -> None:
    """Test nxpdebugmbox CLI template generation functionality.

    This test verifies that the debug authentication configuration template
    can be successfully generated using the CLI command and that the output
    file is created at the specified location.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param family: Target MCU family name for template generation.
    :param revision: Target MCU revision for template generation.
    """
    cmd = [
        "dat",
        "dc",
        "get-template",
        "-f",
        family,
        "-r",
        revision,
        "--output",
        f"{tmpdir}/debugmbox.yml",
    ]
    cli_runner.invoke(main, cmd)
    assert os.path.isfile(f"{tmpdir}/debugmbox.yml")


@pytest.mark.parametrize(
    "family, revision",
    get_all_devices_and_revision(feature="dat", sub_feature="famode_cert"),
)
def test_nxpdebugmbox_famode_get_template(
    cli_runner: CliRunner, tmpdir: Any, family: str, revision: str
) -> None:
    """Test nxpdebugmbox famode-image CLI template generation functionality.

    This test verifies that the famode-image get-templates command correctly
    generates template files in the specified output directory for the given
    family and revision parameters.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param family: Target MCU family name for template generation.
    :param revision: Target MCU revision for template generation.
    """
    cmd = [
        "famode-image",
        "get-templates",
        "-f",
        family,
        "-r",
        revision,
        "--output",
        f"{tmpdir}/debugmbox",
    ]
    cli_runner.invoke(main, cmd)
    assert os.path.isdir(f"{tmpdir}/debugmbox")


def test_nxpimage_famode_export_cli(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test nxpdebugmbox famode-image CLI export functionality.

    This test verifies that the famode-image export command works correctly by:
    1. Setting up a temporary working directory
    2. Using a test configuration file to export a famode image
    3. Verifying that the output file is created successfully

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for test files
    :param data_dir: Path to test data directory containing configuration files
    """
    with use_working_directory(tmpdir):
        config_file = os.path.join(data_dir, "famode-image", "famode_image.yaml")
        output_file = os.path.join(tmpdir, "famode.bin")

        cmd = [
            "famode-image",
            "export",
            "-c",
            config_file,
            "-oc",
            f"masterBootOutputFile={output_file}",
        ]
        cli_runner.invoke(main, cmd)
        assert os.path.isfile(output_file)


def test_nxpimage_famode_parse_cli(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test nxpdebugmbox famode-image CLI parse command.

    This test verifies that the famode-image parse command correctly processes
    a binary file and generates the expected output directory structure.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Path to test data directory containing input files.
    """
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "famode-image")
        binary_path = os.path.join(data_folder, "famode.bin")
        out_config = os.path.join(tmpdir, "famode")
        cmd = [
            "famode-image",
            "parse",
            "-f",
            "kw45b41z5",
            "-b",
            binary_path,
            "-o",
            out_config,
        ]
        cli_runner.invoke(main, cmd)
        assert os.path.isdir(out_config)
