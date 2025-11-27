#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for nxpimage TrustZone functionality.

This module contains comprehensive tests for TrustZone-related features
in the nxpimage application, covering basic operations, export/parse
functionality, and template generation workflows.
"""

import filecmp
import os
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.image.trustzone import TrustZone
from spsdk.utils.misc import (
    load_configuration,
    load_text,
    use_working_directory,
    value_to_int,
    write_file,
)
from tests.cli_runner import CliRunner


@pytest.fixture(scope="module")
def tz_data_dir(data_dir: str) -> str:
    """Get TrustZone data directory path.

    Constructs the path to the TrustZone test data directory by appending 'tz'
    to the provided base data directory path.

    :param data_dir: Base data directory path.
    :return: Path to the TrustZone data directory.
    """
    return f"{data_dir}/tz"


@pytest.mark.parametrize(
    "config_file,output_file,reference_binary",
    [
        ("lpc55s6xA1.yaml", "lpc55s6xA1_tzFile.bin", "lpc55s6xA1_tzFile.bin"),
    ],
)
def test_nxpimage_trustzone_basic(
    cli_runner: CliRunner,
    tz_data_dir: str,
    tmpdir: Any,
    config_file: str,
    output_file: str,
    reference_binary: str,
) -> None:
    """Test basic TrustZone export functionality.

    This test verifies that the TrustZone configuration can be exported to a binary file
    and that the generated binary matches the expected reference binary.

    :param cli_runner: Fixture providing a CLI runner for invoking commands.
    :param tz_data_dir: Path to the directory containing TrustZone test data.
    :param tmpdir: Pytest fixture providing a temporary directory for test files.
    :param config_file: Name of the TrustZone configuration file to use.
    :param output_file: Expected name of the output binary file.
    :param reference_binary: Name of the reference binary file for comparison.
    """
    with use_working_directory(tmpdir):
        write_file(load_text(f"{tz_data_dir}/{config_file}"), config_file)
        cmd = f"tz export -c {config_file}"
        cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/{output_file}")
    assert filecmp.cmp(f"{tz_data_dir}/{reference_binary}", f"{tmpdir}/{output_file}")


@pytest.mark.parametrize(
    "config_file,output_file,reference_binary",
    [
        ("lpc55s6xA1.yaml", "lpc55s6xA1_tzFile.bin", "lpc55s6xA1_tzFile.bin"),
    ],
)
def test_nxpimage_trustzone_export_parse(
    cli_runner: CliRunner,
    tz_data_dir: str,
    tmpdir: Any,
    config_file: str,
    output_file: str,
    reference_binary: str,
) -> None:
    """Test TrustZone export and parse functionality.

    This test verifies that TrustZone configurations can be exported to binary files
    and then parsed back to YAML configurations with all settings preserved.
    The test handles both V1 and V2 TrustZone record formats.

    :param cli_runner: Fixture providing a CLI runner for invoking commands.
    :param tz_data_dir: Path to the directory containing TrustZone test data.
    :param tmpdir: Pytest fixture providing a temporary directory for test files.
    :param config_file: Name of the TrustZone configuration file to use.
    :param output_file: Expected name of the output binary file.
    :param reference_binary: Name of the reference binary file for comparison.
    """
    with use_working_directory(tmpdir):
        write_file(load_text(f"{tz_data_dir}/{config_file}"), config_file)
        cfg = load_configuration(config_file)
        cmd = f"tz export -c {config_file}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        cmd_parse = f"tz parse -f {cfg['family']} -b {output_file} -o parsed.yaml"
        cli_runner.invoke(nxpimage.main, cmd_parse.split())
        assert os.path.isfile("parsed.yaml"), "Trust Zone parse output file not generated"
        parsed_cfg = load_configuration("parsed.yaml")
        parsed_cfg.pop("tzpOutputFile")
        cfg.pop("tzpOutputFile")
        assert parsed_cfg["family"] == cfg["family"], "Family mismatch in parsed configuration"

        if "trustZoneRecords" in parsed_cfg:
            # Version V2 specific parsing
            tz_data_key = "trustZoneRecords"
            assert len(parsed_cfg[tz_data_key]) == len(
                cfg[tz_data_key]
            ), "Number of TrustZone records mismatch"
            assert parsed_cfg[tz_data_key] == cfg[tz_data_key], "TrustZone records content mismatch"

        else:
            tz_data_key = "trustZonePreset"
            for k, v in cfg[tz_data_key].items():
                assert k in parsed_cfg[tz_data_key], f"Missing TrustZone record: {k}"
                assert value_to_int(v) == value_to_int(
                    parsed_cfg[tz_data_key][k]
                ), f"TrustZone record mismatch for {k}"


def test_generate_template(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test TrustZone template generation for all supported families.

    This test verifies that the 'tz get-template' command successfully generates
    template configuration files for all supported device families. The test
    iterates through all supported families, executes the template generation
    command, and validates both command success and file creation.

    :param cli_runner: CLI runner fixture for invoking nxpimage commands
    :param tmpdir: Temporary directory fixture for test file operations
    """
    with use_working_directory(tmpdir):
        families = list(set([x.name for x in TrustZone.get_supported_families()]))
        for family in families:
            cmd = f"tz get-template -f {family} -o {family}.yaml"
            result = cli_runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0, f"Trust Zone generate template failed on {family}"
            assert os.path.isfile(
                f"{family}.yaml"
            ), f"Trust Zone generate template failed on {family}, missing file"
