#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for XMCD functionality in nxpimage application.

This module contains comprehensive tests for External Memory Configuration Data (XMCD)
handling within the nxpimage tool, covering export, parsing, template generation,
validation, and CRC calculation functionality.
"""

import filecmp
import os
from typing import Any, Optional

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.xmcd.xmcd import XMCD, MemoryType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import (
    load_binary,
    load_configuration,
    load_file,
    use_working_directory,
    write_file,
)
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family,mem_type,config_type,option",
    [
        ("mimxrt1176", "semc_sdram", "simplified", None),
        ("mimxrt1176", "semc_sdram", "full", None),
        ("mimxrt1176", "flexspi_ram", "simplified", 0),
        ("mimxrt1176", "flexspi_ram", "simplified", 1),
        ("mimxrt1176", "flexspi_ram", "full", None),
        ("mimxrt1166", "semc_sdram", "simplified", None),
        ("mimxrt1166", "semc_sdram", "full", None),
        ("mimxrt1166", "flexspi_ram", "simplified", 0),
        ("mimxrt1166", "flexspi_ram", "simplified", 1),
        ("mimxrt1166", "flexspi_ram", "full", None),
        ("mimxrt798s", "xspi_ram", "simplified", None),
    ],
)
def test_nxpimage_xmcd_export(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    mem_type: str,
    config_type: str,
    option: Optional[int],
) -> None:
    """Test XMCD export functionality through CLI interface.

    This test verifies that the XMCD export command correctly generates binary files
    from YAML configuration files and that the output matches expected reference files.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for XMCD configuration.
    :param mem_type: Memory type identifier for XMCD configuration.
    :param config_type: Configuration type identifier for XMCD.
    :param option: Optional configuration variant number.
    """
    with use_working_directory(data_dir):
        file_base_name = f"{mem_type}_{config_type}"
        if option is not None:
            file_base_name += f"_{option}"
        config_file_path = os.path.join(data_dir, "xmcd", family, f"{file_base_name}.yaml")
        out_file = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}_exported.bin")
        cmd = ["bootable-image", "xmcd", "export", "-c", config_file_path, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "xmcd", family, f"{file_base_name}.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,config_type,option",
    [
        ("mimxrt1176", "semc_sdram", "simplified", None),
        ("mimxrt1176", "semc_sdram", "full", None),
        ("mimxrt1176", "flexspi_ram", "simplified", 0),
        ("mimxrt1176", "flexspi_ram", "simplified", 1),
        ("mimxrt1176", "flexspi_ram", "full", None),
        ("mimxrt1166", "semc_sdram", "simplified", None),
        ("mimxrt1166", "semc_sdram", "full", None),
        ("mimxrt1166", "flexspi_ram", "simplified", 0),
        ("mimxrt1166", "flexspi_ram", "simplified", 1),
        ("mimxrt1166", "flexspi_ram", "full", None),
        ("mimxrt798s", "xspi_ram", "simplified", None),
    ],
)
def test_nxpimage_xmcd_parse_cli(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    mem_type: str,
    config_type: str,
    option: Optional[int],
) -> None:
    """Test CLI parsing of XMCD binary files to YAML configuration.

    This test verifies that the nxpimage CLI can successfully parse XMCD (External Memory Configuration Data)
    binary files and convert them to YAML configuration format for various memory types and configurations.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name.
    :param mem_type: Memory type identifier.
    :param config_type: Configuration type identifier.
    :param option: Optional configuration option number.
    """
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "xmcd", family)
        output_file = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}.yaml")
        file_base_name = f"{mem_type}_{config_type}"
        if option is not None:
            file_base_name += f"_{option}"
        bin_path = os.path.join(data_folder, f"{file_base_name}.bin")

        cmd = [
            "bootable-image",
            "xmcd",
            "parse",
            "-f",
            family,
            "-b",
            bin_path,
            "-o",
            output_file,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(output_file)


@pytest.mark.parametrize(
    "family",
    ["mimxrt1176", "mimxrt1166", "mimxrt1189", "mimxrt798s"],
)
def test_nxpimage_xmcd_template_cli(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, family: str
) -> None:
    """Test XMCD template generation CLI command.

    Verifies that the bootable-image xmcd get-templates command correctly generates
    template files for all supported memory types and configuration types for a given family.
    The test checks that all expected template files are created in the output directory.

    :param cli_runner: CLI test runner fixture for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Test data directory path.
    :param family: Target MCU family name for template generation.
    """
    cmd = f"bootable-image xmcd get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    mem_types = XMCD.get_supported_memory_types(FamilyRevision(family))
    for mem_type in mem_types:
        config_types = XMCD.get_supported_configuration_types(FamilyRevision(family), mem_type)
        for config_type in config_types:
            template_name = f"xmcd_{family}_{mem_type.label}_{config_type.label}.yaml"
            new_template_path = os.path.join(tmpdir, template_name)
            assert os.path.isfile(new_template_path)


@pytest.mark.parametrize(
    "mem_type,config_type,option",
    [
        ("semc_sdram", "simplified", None),
        ("semc_sdram", "full", None),
        ("flexspi_ram", "simplified", 0),
        ("flexspi_ram", "simplified", 1),
        ("flexspi_ram", "full", None),
    ],
)
def test_nxpimage_xmcd_export_invalid(
    data_dir: str, mem_type: str, config_type: str, option: Optional[int]
) -> None:
    """Test XMCD export functionality with invalid configurations.

    This test validates that XMCD.load_from_config properly raises SPSDKError
    when provided with invalid configuration data, including missing mandatory
    fields, invalid memory types, invalid configuration types, and unsupported
    device families.

    :param data_dir: Base directory containing test data files.
    :param mem_type: Memory type identifier for the test configuration.
    :param config_type: Configuration type identifier for the test.
    :param option: Optional parameter to modify the configuration file name.
    :raises SPSDKError: When XMCD configuration validation fails as expected.
    """
    file_base_name = f"{mem_type}_{config_type}"
    if option is not None:
        file_base_name += f"_{option}"
    config = os.path.join(data_dir, "xmcd", "mimxrt1166", f"{file_base_name}.yaml")
    mandatory_fields = ["family", "mem_type", "config_type", "xmcd_settings"]
    # Check mandatory fields
    for mandatory_field in mandatory_fields:
        config_data = load_configuration(config)
        config_data.pop(mandatory_field)
        with pytest.raises(SPSDKError):
            XMCD.load_from_config(Config(config_data))
    # Check invalid mem_type
    config_data = load_configuration(config)
    config_data["mem_type"] = "unknown"
    with pytest.raises(SPSDKError):
        XMCD.load_from_config(Config(config_data))
    # Check invalid config_type
    config_data = load_configuration(config)
    config_data["config_type"] = "unknown"
    with pytest.raises(SPSDKError):
        XMCD.load_from_config(Config(config_data))
    # Check unsupported family
    config_data = load_configuration(config)
    config_data["family"] = "rt5xx"
    with pytest.raises(SPSDKError):
        XMCD.load_from_config(Config(config_data))


def test_nxpimage_supported_mem_types() -> None:
    """Test XMCD supported memory types functionality.

    Verifies that the XMCD class returns the correct number and types of
    supported memory types. The test checks that exactly 3 memory types
    are supported and validates the specific memory types returned.
    """
    mem_types = XMCD.get_supported_memory_types()
    assert len(mem_types) == 3
    mem_types[0] == MemoryType.FLEXSPI_RAM
    mem_types[0] == MemoryType.SEMC_SDRAM
    mem_types[0] == MemoryType.XSPI_RAM


def test_nxpimage_xmcd_validate(
    caplog: Any, cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test XMCD validation functionality through CLI interface.

    Tests both valid and invalid XMCD configurations by creating XMCD objects from config files,
    exporting them to binary format, and validating them using the nxpimage CLI tool.
    Verifies that valid configurations pass validation and invalid configurations fail with
    appropriate error messages.

    :param caplog: Pytest log capture fixture for controlling log levels.
    :param cli_runner: Click CLI runner fixture for testing command-line interface.
    :param tmpdir: Temporary directory path for storing test files.
    :param data_dir: Path to test data directory containing XMCD configuration files.
    """
    family = "mimxrt1166"
    caplog.set_level(100_000)
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "xmcd", family, "semc_sdram_simplified.yaml")
        # Test Valid
        config = Config.create_from_file(config_file)
        xmcd = XMCD.load_from_config(config)
        bin_path = os.path.join(tmpdir, "xmcd.bin")
        write_file(xmcd.export(), bin_path, mode="wb")

        cmd = [
            "bootable-image",
            "xmcd",
            "verify",
            "-f",
            family,
            "-b",
            bin_path,
        ]
        result = cli_runner.invoke(nxpimage.main, cmd)
        assert "XMCD(Succeeded)" in result.output
        # Test Invalid
        config = Config.create_from_file(config_file)
        config["xmcd_settings"]["header"]["bitfields"]["tag"] = 14
        xmcd = XMCD.load_from_config(config)
        write_file(xmcd.export(), bin_path, mode="wb")
        result = cli_runner.invoke(nxpimage.main, cmd, expected_code=1)
        assert "XMCD Header(Error)" in result.output
        assert "Tag(Error): 0xc" in result.output


@pytest.mark.parametrize(
    "mem_type,config_type,expected_crc",
    [
        ("semc_sdram", "simplified", "bc333806"),
        ("semc_sdram", "full", "762a8d08"),
        ("flexspi_ram", "full", "fb45c9eb"),
        ("flexspi_ram", "simplified_0", "ee57b489"),
        ("flexspi_ram", "simplified_1", "20fa163a"),
    ],
)
def test_nxpimage_xmcd_crc(
    data_dir: str, mem_type: str, config_type: str, expected_crc: str
) -> None:
    """Test XMCD CRC validation against expected value.

    This test method verifies that the CRC calculated for an XMCD (External Memory Configuration Data)
    object matches the expected CRC value. It loads a binary file containing XMCD data, parses it
    using the MIMXRT1176 family configuration, and compares the computed CRC with the expected result.

    :param data_dir: Base directory path containing test data files
    :param mem_type: Memory type identifier used in the binary filename
    :param config_type: Configuration type identifier used in the binary filename
    :param expected_crc: Expected CRC value as hexadecimal string for comparison
    :raises AssertionError: When computed CRC doesn't match expected CRC value
    :raises SPSDKError: When binary file loading or XMCD parsing fails
    """
    family = FamilyRevision("mimxrt1176")
    data_folder = os.path.join(data_dir, "xmcd", family.name)
    bin_path = os.path.join(data_folder, f"{mem_type}_{config_type}.bin")
    xmcd = XMCD.parse(load_binary(bin_path), family=family)
    assert xmcd.crc == bytes.fromhex(expected_crc)


@pytest.mark.parametrize(
    "family,crc_sum_fuse_id",
    [("mimxrt1166", 73), ("mimxrt1176", 73), ("mimxrt1189", 32)],
)
def test_nxpimage_xmcd_crc_fuses_script(
    cli_runner: CliRunner, tmpdir: str, data_dir: str, family: str, crc_sum_fuse_id: int
) -> None:
    """Test XMCD CRC fuses script generation functionality.

    This test verifies that the nxpimage CLI can generate a proper fuses programming
    script for XMCD CRC values. It uses a sample XMCD binary file and validates
    that the generated script contains the expected content including family info,
    warnings, and the correct efuse programming command.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory path for output files
    :param data_dir: Path to test data directory containing XMCD binaries
    :param family: Target MCU family name for the fuses script
    :param crc_sum_fuse_id: Expected CRC sum fuse identifier in the output
    """
    # we take any XMCD binary as there are no differences between families
    binary_path = os.path.join(data_dir, "xmcd", "mimxrt1176", "semc_sdram_simplified.bin")
    fuses_script = os.path.join(tmpdir, "fuses.txt")
    cmd = [
        "bootable-image",
        "xmcd",
        "crc-fuses-script",
        "-b",
        binary_path,
        "-f",
        family,
        "-o",
        fuses_script,
    ]
    result = cli_runner.invoke(nxpimage.main, cmd)
    assert "Created fuses script" in result.output
    content = load_file(fuses_script, mode="r")
    assert "blhost XMCD CRC fuses programming script" in content
    assert f"Family: {family}, Revision: latest" in content
    assert "WARNING! Partially set register, check all bitfields before writing" in content
    assert f"efuse-program-once {crc_sum_fuse_id} 0xBC333806" in content
