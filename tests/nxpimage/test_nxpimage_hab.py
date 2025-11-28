#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test suite for SPSDK nxpimage HAB container functionality.

This module contains comprehensive tests for the HAB (High Assurance Boot) container
functionality in the nxpimage tool, covering CLI operations and various authentication
methods including RSA and ECC signing, format conversion, and template generation.
"""

import filecmp
import os
import shutil
from shutil import copytree
from typing import Any
from unittest.mock import patch

import pytest

from spsdk.apps import nxpimage
from spsdk.image.hab.hab_image import HabImage
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner
from tests.misc import GetPassMock


@pytest.fixture()
def hab_data_dir(data_dir: str) -> str:
    """Get HAB data directory path.

    Constructs the path to the HAB (High Assurance Boot) data directory
    by joining the provided data directory with the 'hab' subdirectory.

    :param data_dir: Base data directory path.
    :return: Path to the HAB data subdirectory.
    """
    return os.path.join(data_dir, "hab")


def export_hab_cli(cli_runner: CliRunner, output_path: str, config_path: str) -> None:
    """Export HAB configuration using the CLI interface.

    Invokes the nxpimage CLI tool with HAB export command to generate HAB (High Assurance Boot)
    configuration files based on the provided configuration.

    :param cli_runner: CLI test runner instance for invoking commands.
    :param output_path: Path where the exported HAB files will be saved.
    :param config_path: Path to the HAB configuration file to be processed.
    """
    cmd = ["hab", "export", "--config", config_path, "--output", output_path, "--force"]

    cli_runner.invoke(nxpimage.main, cmd)


@pytest.mark.parametrize(
    "configuration",
    [
        "rt1160_xip_mdk_unsigned",
        "rt1170_QSPI_flash_unsigned",
        "rt1170_RAM_non_xip_unsigned",
        "rt1170_RAM_unsigned",
        "rt1170_flashloader_unsigned",
        "rt1170_RAM_unsigned_xmcd",
    ],
)
def test_nxpimage_hab_export_unsigned(
    cli_runner: CliRunner, tmpdir: Any, hab_data_dir: str, configuration: str
) -> None:
    """Test HAB image export functionality for unsigned images.

    Verifies that the nxpimage HAB export command correctly generates an unsigned
    binary image that matches the expected reference output. The test uses a
    temporary directory to isolate file operations and compares the generated
    binary with a reference binary byte-by-byte.

    :param cli_runner: Click CLI test runner for executing command line operations
    :param tmpdir: Temporary directory fixture for test file isolation
    :param hab_data_dir: Base directory path containing HAB test data files
    :param configuration: Configuration name identifying the specific test case setup
    """
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    with use_working_directory(tmpdir):
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(
            cli_runner,
            output_file_path,
            os.path.join(config_dir, "config.yaml"),
        )
        assert os.path.isfile(output_file_path)
        ref_binary = load_binary(os.path.join(config_dir, "output.bin"))
        new_binary = load_binary(output_file_path)
        assert len(ref_binary) == len(new_binary)
        assert ref_binary == new_binary


@patch("spsdk.crypto.keys.getpass", GetPassMock("test"))
@pytest.mark.parametrize(
    "configuration, config_files",
    [
        ("rt1040_srk_revoke_uid", ["config.yaml"]),
        ("rt1040_srk_revoke_command", ["config.yaml"]),
        (
            "rt1050_xip_image_iar_authenticated",
            [
                "config_pk_encrypted.yaml",
                "config_sp.yaml",
                "config_pk.yaml",
                "config_pk_simplified.yaml",
            ],
        ),
        ("rt1060_flashloader_authenticated_nocak", ["config.yaml"]),
        ("rt1160_RAM_encrypted", ["config.yaml"]),
        ("rt1165_flashloader_authenticated", ["config.yaml"]),
        ("rt1165_semcnand_authenticated", ["config.yaml"]),
        ("rt1165_semcnand_encrypted", ["config.yaml"]),
        ("rt1170_flashloader_authenticated", ["config.yaml"]),
        ("rt1170_RAM_authenticated", ["config.yaml"]),
        ("rt1170_semcnand_authenticated", ["config.yaml"]),
    ],
)
def test_nxpimage_hab_export_authenticated_rsa(
    cli_runner: CliRunner,
    tmpdir: Any,
    hab_data_dir: str,
    configuration: str,
    config_files: list[str],
) -> None:
    """Test HAB export functionality with RSA authenticated images.

    This test verifies that the HAB (High Assurance Boot) export command correctly
    generates authenticated images using RSA signatures by comparing the output
    with reference binaries for multiple configuration files.

    :param cli_runner: Click CLI test runner for executing commands.
    :param tmpdir: Temporary directory for test file operations.
    :param hab_data_dir: Base directory containing HAB test data files.
    :param configuration: Configuration name identifying the test scenario.
    :param config_files: List of configuration file names to test.
    """
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    for config_file in config_files:
        with use_working_directory(tmpdir):
            output_file_path = os.path.join(tmpdir, "image_output.bin")
            export_hab_cli(
                cli_runner,
                output_file_path,
                os.path.join(config_dir, config_file),
            )
            assert os.path.isfile(output_file_path)
            ref_binary = load_binary(os.path.join(config_dir, "output.bin"))
            new_binary = load_binary(output_file_path)
            assert len(ref_binary) == len(new_binary)
            assert ref_binary == new_binary


@patch("spsdk.crypto.keys.getpass", GetPassMock("test"))
@pytest.mark.parametrize(
    "config_file",
    ["config_pk_encrypted.yaml", "config_pk.yaml", "config_sp.yaml"],
)
def test_nxpimage_hab_export_authenticated_ecc(
    cli_runner: CliRunner, tmpdir: Any, config_file: str, hab_data_dir: str
) -> None:
    """Test HAB image export with ECC authentication.

    Tests the export functionality for HAB images signed with ECC keys. The image
    cannot be verified as binary compare since the signature length may change
    and therefore the data reference in CSF commands may change.

    :param cli_runner: Click CLI runner for testing command line interface.
    :param tmpdir: Temporary directory for test output files.
    :param config_file: Configuration file name for HAB image generation.
    :param hab_data_dir: Directory containing HAB test data files.
    """
    config_dir = os.path.join(hab_data_dir, "export", "rt1173_flashloader_authenticated_ecc")
    output_file_path = os.path.join(tmpdir, "image_output.bin")
    export_hab_cli(
        cli_runner,
        output_file_path,
        os.path.join(config_dir, config_file),
    )
    assert os.path.isfile(output_file_path)
    hab = HabImage.parse(load_binary(output_file_path), FamilyRevision("mimxrt1173"))
    assert hab.app_segment
    assert hab.bdt_segment
    assert hab.csf_segment
    assert not hab.dcd_segment
    assert not hab.xmcd_segment
    assert len(hab.csf_segment.commands) == 6


@pytest.mark.parametrize(
    "configuration, app_name",
    [
        (
            "rt1160_xip_mdk_unsigned",
            "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.srec",
        ),
        (
            "rt1170_QSPI_flash_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.s19",
        ),
        (
            "rt1170_RAM_non_xip_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.s19",
        ),
        ("rt1170_RAM_unsigned", "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.s19"),
        ("rt1170_flashloader_unsigned", "evkmimxrt1170_flashloader.srec"),
        ("rt1170_flashloader_authenticated", "flashloader.srec"),
        ("rt1170_RAM_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19"),
        ("rt1050_xip_image_iar_authenticated", "led_blinky_xip_srec_iar.srec"),
        ("rt1170_semcnand_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19"),
        ("rt1060_flashloader_authenticated_nocak", "flashloader.srec"),
        ("rt1165_semcnand_authenticated", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        ("rt1165_flashloader_authenticated", "flashloader.srec"),
        ("rt1165_semcnand_encrypted", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        (
            "rt1160_RAM_encrypted",
            "validationboard_imxrt1160_iled_blinky_cm7_int_RAM.s19",
        ),
    ],
)
def test_nxpimage_hab_convert(
    cli_runner: CliRunner, tmpdir: Any, hab_data_dir: str, configuration: str, app_name: str
) -> None:
    """Test HAB image conversion from BD command file to YAML configuration.

    This test verifies the conversion functionality by copying test data to a temporary
    directory, converting a BD command file to YAML configuration, generating an image
    from the converted configuration, and comparing the output with a reference binary.

    :param cli_runner: CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory for test files and outputs.
    :param hab_data_dir: Base directory containing HAB test data and configurations.
    :param configuration: Name of the specific configuration subdirectory to test.
    :param app_name: Name of the application binary file to process.
    """
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    tmp_config_dir = os.path.join(tmpdir, configuration)
    shutil.copytree(config_dir, tmp_config_dir, dirs_exist_ok=True)
    shutil.copytree(
        os.path.join(hab_data_dir, "export", "keys"),
        os.path.join(tmpdir, "keys"),
        dirs_exist_ok=True,
    )
    shutil.copytree(
        os.path.join(hab_data_dir, "export", "crts"),
        os.path.join(tmpdir, "crts"),
        dirs_exist_ok=True,
    )
    command_file_path = os.path.join(config_dir, "config.bd")
    ref_file_path = os.path.join(config_dir, "output.bin")
    app_file_path = os.path.join(config_dir, app_name)
    with use_working_directory(tmpdir):
        converted_config = os.path.join(tmp_config_dir, "config.yaml")
        cmd = [
            "hab",
            "convert",
            "--command",
            command_file_path,
            "--output",
            converted_config,
            app_file_path,
            "--force",
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(converted_config)

        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(cli_runner, output_file_path, converted_config)
        assert os.path.isfile(output_file_path)
        assert load_binary(ref_file_path) == load_binary(output_file_path)


@pytest.mark.parametrize(
    "configuration, family, segments",
    [
        (
            "rt1170_RAM_unsigned",
            FamilyRevision("mimxrt1176"),
            ["ivt", "bdt", "app"],
        ),
        (
            "rt1050_ext_xip_unsigned",
            FamilyRevision("mimxrt1050"),
            ["ivt", "bdt", "app"],
        ),
    ],
)
def test_nxpimage_hab_parse(
    cli_runner: CliRunner,
    tmpdir: Any,
    hab_data_dir: str,
    configuration: str,
    family: FamilyRevision,
    segments: list[str],
) -> None:
    """Test HAB container parsing functionality using CLI.

    This test verifies that the nxpimage HAB parse command correctly extracts
    segments from a HAB container binary file and compares the output files
    with expected reference files.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param hab_data_dir: Base directory containing HAB test data.
    :param configuration: Configuration name identifying the test case.
    :param family: Target MCU family and revision for HAB processing.
    :param segments: List of expected segment names to be extracted.
    """
    config_dir = os.path.join(hab_data_dir, "parse", configuration)
    source_bin_path = os.path.join(config_dir, "hab_container.bin")
    with use_working_directory(tmpdir):
        cmd = [
            "hab",
            "parse",
            "--binary",
            source_bin_path,
            "--family",
            family.name,
            "--output",
            str(tmpdir),
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        for segment in segments:
            segment_file_name = f"{segment}.bin"
            segment_file_path = os.path.join(tmpdir, segment_file_name)
            assert os.path.isfile(segment_file_path)
            assert filecmp.cmp(
                os.path.join(config_dir, segment_file_name),
                segment_file_path,
                shallow=False,
            )


def test_nxpimage_hab_export_secret_key_generated(
    cli_runner: CliRunner, tmpdir: Any, hab_data_dir: str
) -> None:
    """Test HAB export functionality with generated secret key.

    This test verifies that the HAB export command correctly generates and exports
    a secret key when processing an encrypted configuration. It sets up a temporary
    directory with HAB configuration files, executes the export command, and validates
    that both the output image and the generated secret key file are created with
    the expected properties.

    :param cli_runner: Click CLI test runner for executing command line operations.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param hab_data_dir: Path to the directory containing HAB test data files.
    :raises AssertionError: If the output image file, secret key file is not created, or secret key length is invalid.
    """
    config_dir = os.path.join(hab_data_dir, "export", "rt1165_semcnand_encrypted_random")
    tmp_config_dir = os.path.join(tmpdir, "rt1165_semcnand_encrypted_random")
    with use_working_directory(tmpdir):
        copytree(config_dir, tmp_config_dir, dirs_exist_ok=True)
        copytree(
            os.path.join(hab_data_dir, "export", "keys"),
            os.path.join(tmpdir, "keys"),
            dirs_exist_ok=True,
        )
        copytree(
            os.path.join(hab_data_dir, "export", "crts"),
            os.path.join(tmpdir, "crts"),
            dirs_exist_ok=True,
        )
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(
            cli_runner,
            output_file_path,
            os.path.join(tmp_config_dir, "config.yaml"),
        )
        assert os.path.isfile(output_file_path)
        secret_key_path = os.path.join(
            tmp_config_dir, "gen_hab_encrypt", "evkmimxrt1064_iled_blinky_SDRAM_hab_dek.bin"
        )
        assert os.path.isfile(secret_key_path)
        secret_key = load_binary(secret_key_path)
        assert len(secret_key) == 32


def test_nxpimage_hab_template_cli(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test HAB template CLI command functionality.

    Verifies that the HAB get-template command successfully generates a template file
    for the specified family and saves it to the designated output path.

    :param cli_runner: CLI test runner for invoking command-line interface.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    template = os.path.join(tmpdir, "hab_template.yaml")
    cmd = [
        "hab",
        "get-template",
        "-f",
        "mimxrt1050",
        "--output",
        template,
    ]
    cli_runner.invoke(nxpimage.main, cmd)
    assert os.path.isfile(template)
