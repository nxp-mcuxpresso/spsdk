#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR CLI application test suite.

This module contains comprehensive tests for the PFR (Protected Flash Region)
command-line interface functionality, covering configuration generation,
validation, and export operations for NXP MCU secure provisioning.
"""

import filecmp
import logging
import os

import pytest
from ruamel.yaml import YAML

from spsdk.apps import pfr as cli
from spsdk.pfr.pfr import CMPA
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner


def test_command_line_interface(cli_runner: CliRunner) -> None:
    """Test the CLI main command help functionality.

    Validates that the CLI main command responds correctly to the --help flag
    and displays the expected help message content.

    :param cli_runner: Click CLI test runner for invoking CLI commands.
    """
    result = cli_runner.invoke(cli.main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "name,type",
    [
        ("lpc55s6x", "cmpa"),
        ("lpc55s6x", "cfpa"),
        ("lpc55s3x", "cmpa"),
        ("lpc55s3x", "cfpa"),
        ("mcxa1xx", "cmpa"),
        ("mcxa156", "cmpa"),
        ("mcxa155", "cmpa"),
        ("mcxa154", "cmpa"),
        ("mcxa144", "cmpa"),
        ("mcxa145", "cmpa"),
        ("mcxa146", "cmpa"),
        ("mcxa142", "cmpa"),
        ("mcxa143", "cmpa"),
        ("mcxa152", "cmpa"),
        ("mcxa153", "cmpa"),
        ("mcxn9xx", "cmpa"),
        ("mcxn9xx", "cfpa"),
        ("nhs52sxx", "cmpa"),
        ("nhs52sxx", "cfpa"),
        ("mcxn556s", "cmpa"),
        ("mcxl255", "cmpa"),
    ],
)
def test_generate_all(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, name: str, type: str
) -> None:
    """Test PFR CLI export command for generating CMPA binary files.

    Validates that the PFR CLI export command correctly generates binary files
    for all supported device types by comparing generated output with expected
    reference files.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Base directory containing test data files.
    :param tmpdir: Temporary directory for output files.
    :param name: Device name identifier for test files.
    :param type: Device type identifier for test files.
    """
    test_data_dir = os.path.join(data_dir, "yaml_bin")

    cmd = [
        "export",
        "--output",
        f"{tmpdir}/{name}_{type}.bin",
        "--config",
        f"{test_data_dir}/{name}_{type}.yaml",
        "--ignore",  # Omit PFRC tests
    ]
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    new_data = load_binary(f"{tmpdir}/{name}_{type}.bin")
    expected = load_binary(f"{test_data_dir}/{name}_{type}.bin")
    assert new_data == expected


def test_generate_cmpa_validate_export(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test CMPA export command with different configuration combinations.

    This test validates that the CMPA export command produces identical binary output
    when using different configuration approaches: basic config, cert block config,
    MBI config, and secret file config. It ensures consistency across different
    configuration methods for the same target device.

    :param cli_runner: CLI test runner for invoking commands.
    :param data_dir: Directory containing test data files and configurations.
    :param tmpdir: Temporary directory for output files.
    """
    out_file = os.path.join(tmpdir, "cmpa_mcxn9xx.bin")
    cmd_cmpa_config = [
        "export",
        "--output",
        out_file,
        "--config",
        os.path.join(data_dir, "cmpa_mcxn9xx.yaml"),
    ]
    cmd_cert_block_config = cmd_cmpa_config + [
        "--rot-config",
        os.path.join(data_dir, "cert_block_v21.yaml"),
    ]
    cmd_mbi_config = cmd_cmpa_config + [
        "--rot-config",
        os.path.join(data_dir, "mbi_config_mcxn9xx.yaml"),
    ]
    cmd_secret_file = cmd_cmpa_config + [
        "--secret-file",
        os.path.join(data_dir, "keys", "ROT1_p384.pem"),
        "--secret-file",
        os.path.join(data_dir, "keys", "ROT2_p384.pem"),
        "--secret-file",
        os.path.join(data_dir, "keys", "ROT3_p384.pem"),
        "--secret-file",
        os.path.join(data_dir, "keys", "ROT4_p384.pem"),
    ]

    reference_binary = b""
    for cmd in [cmd_cmpa_config, cmd_cert_block_config, cmd_mbi_config, cmd_secret_file]:
        cli_runner.invoke(cli.main, cmd)
        assert os.path.isfile(out_file)
        if not reference_binary:
            reference_binary = load_binary(out_file)
            continue
        assert reference_binary == load_binary(out_file)


def test_generate_cmpa(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test PFR CLI command for generating CMPA binary output.

    Validates that the PFR export command correctly generates a CMPA (Customer Manufacturing
    Programming Area) binary file by comparing the generated output against expected reference
    data. The test uses a 96MHz configuration with RSA2048 private key for signing.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test input files and expected outputs.
    :param tmpdir: Temporary directory path for generated test outputs.
    """
    cmd = [
        "export",
        "--output",
        f"{tmpdir}/pnd.bin",
        "--config",
        f"{data_dir}/cmpa_96mhz.json",
        "--secret-file",
        f"{data_dir}/selfsign_privatekey_rsa2048.pem",
    ]
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    new_data = open(f"{tmpdir}/pnd.bin", "rb").read()
    expected = open(f"{data_dir}/CMPA_96MHz.bin", "rb").read()
    assert new_data == expected


def test_generate_cmpa_with_elf2sb(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test PFR CLI generation of CMPA binary with elf2sb configuration.

    This test verifies that the PFR CLI can generate CMPA binaries using different
    methods: direct key specification via command line and key specification through
    elf2sb configuration files. It ensures that both approaches produce identical
    results and validates error handling for invalid configurations.

    :param cli_runner: CLI test runner for invoking command-line interface.
    :param data_dir: Directory path containing test data files and configurations.
    :param tmpdir: Temporary directory path for output file generation.
    """
    org_file = f"{tmpdir}/org.bin"
    new_file = f"{tmpdir}/new.bin"
    big_file = f"{tmpdir}/big.bin"

    cmd = "export --config cmpa_96mhz.json"
    # basic usage when keys are passed on command line
    cmd1 = cmd + f" -o {org_file} -sf rotk0_rsa_2048.pub -sf rotk1_rsa_2048.pub"
    # elf2sb config file contains previous two keys + one empty line + 4th entry is not present
    cmd2 = cmd + f" -o {new_file} -e elf2sb_config.json"
    # mbi config contains path to cert_block yaml
    cmd3 = (
        cmd
        + f" -o {big_file} -e big_elf2sb_config.json -sf rotk0_rsa_2048.pub -sf rotk1_rsa_2048.pub"
    )
    with use_working_directory(data_dir):
        cli_runner.invoke(cli.main, cmd1.split())
        cli_runner.invoke(cli.main, cmd2.split())
        cli_runner.invoke(cli.main, cmd3.split(), expected_code=-1)
    assert filecmp.cmp(org_file, new_file)


def test_generate_cmpa_with_elf2sb_lpc55s3x(data_dir: str, tmpdir: str) -> None:
    """Test PFR CLI command for generating CMPA binary with elf2sb configuration.

    This test verifies that the PFR export command can successfully generate a CMPA
    (Customer Manufacturing Programming Area) binary file using elf2sb configuration
    for LPC55S3x devices. The test compares the generated output with a reference file
    to ensure correctness.

    :param data_dir: Directory path containing test data files including configuration
                     files and reference binary.
    :param tmpdir: Temporary directory path where the generated output file will be
                   created.
    :raises AssertionError: If the CLI command fails or generated file doesn't match
                            reference file.
    """
    new = f"{tmpdir}/new.bin"
    org = "cmpa_lpc55s3x.bin"
    cmd = f"export --config cmpa_lpc55s3x.json -e mbi_config_lpc55s3x.yaml -o {new}"

    with use_working_directory(data_dir):
        result = CliRunner().invoke(cli.main, cmd.split())
        assert result.exit_code == 0, result.output
        assert filecmp.cmp(org, new)


def test_generate_cmpa_raw(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test PFR CLI export command for CMPA binary generation.

    Verifies that the PFR CLI export command correctly generates a CMPA binary file
    from a YAML configuration file by comparing the output with expected binary data.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Path to directory containing test data files.
    :param tmpdir: Path to temporary directory for output files.
    """
    cmd = [
        "export",
        "--output",
        f"{tmpdir}/cmpa_raw.bin",
        "--config",
        f"{data_dir}/cmpa_mcxn9xx_raw.yaml",
    ]
    cli_runner.invoke(cli.main, cmd)
    new_data = open(f"{tmpdir}/cmpa_raw.bin", "rb").read()
    expected = open(f"{data_dir}/cmpa_mcxn9xx_raw.bin", "rb").read()
    assert new_data == expected


def test_parse(cli_runner: CliRunner, data_dir: str, tmpdir: str) -> None:
    """Test PFR CLI parsing functionality for CMPA binary files.

    Validates that the PFR CLI can successfully parse a CMPA binary file and generate
    a configuration file that produces equivalent CMPA data when loaded back.

    :param cli_runner: Click CLI test runner for executing commands.
    :param data_dir: Path to directory containing test data files.
    :param tmpdir: Temporary directory path for output files.
    """
    cmd = [
        "parse",
        "--family",
        "lpc55s69",
        "--type",
        "cmpa",
        "--binary",
        f"{data_dir}/CMPA_96MHz.bin",
        "--show-diff",
        "--output",
        f"{tmpdir}/config.yml",
    ]

    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    new_cfg = Config.create_from_file(f"{tmpdir}/config.yml")
    expected_cfg = Config.create_from_file(f"{data_dir}/cmpa_96mhz_rotkh.yml")
    created = CMPA.load_from_config(new_cfg)
    expected = CMPA.load_from_config(expected_cfg)
    assert created == expected


@pytest.mark.parametrize(
    "family,type",
    [
        ("lpc5506", "cfpa"),
        ("lpc5506", "cmpa"),
        ("lpc5516", "cfpa"),
        ("lpc5516", "cmpa"),
        ("lpc5528", "cfpa"),
        ("lpc5528", "cmpa"),
        ("lpc5536", "cfpa"),
        ("lpc5536", "cmpa"),
        ("lpc55s06", "cfpa"),
        ("lpc55s06", "cmpa"),
        ("lpc55s16", "cfpa"),
        ("lpc55s16", "cmpa"),
        ("lpc55s26", "cfpa"),
        ("lpc55s26", "cmpa"),
        ("lpc55s36", "cfpa"),
        ("lpc55s36", "cmpa"),
        ("lpc55s69", "cfpa"),
        ("lpc55s69", "cmpa"),
        ("mcxa132", "cmpa"),
        ("mcxa133", "cmpa"),
        ("mcxa142", "cmpa"),
        ("mcxa143", "cmpa"),
        ("mcxa144", "cmpa"),
        ("mcxa145", "cmpa"),
        ("mcxa146", "cmpa"),
        ("mcxa152", "cmpa"),
        ("mcxa153", "cmpa"),
        ("mcxn556s", "cmpa"),
        ("mcxl255", "cmpa"),
        ("mcxl254", "cmpa"),
        ("mcxa154", "cmpa"),
        ("mcxa155", "cmpa"),
        ("mcxa156", "cmpa"),
        ("mcxa173", "cmpa"),
        ("mcxa174", "cmpa"),
        ("mcxa255", "cmpa"),
        ("mcxa256", "cmpa"),
        ("mcxa265", "cmpa"),
        ("mcxa266", "cmpa"),
        ("mcxa365", "cmpa"),
        ("mcxa366", "cmpa"),
        ("mcxa343", "cmpa"),
        ("mcxa344", "cmpa"),
        ("mcxa345", "cmpa"),
        ("mcxa346", "cmpa"),
        ("mcxa355", "cmpa"),
        ("mcxa356", "cmpa"),
        ("mcxa365", "cmpa"),
        ("mcxa366", "cmpa"),
        ("mcxl253", "cmpa"),
        ("mcxl254", "cmpa"),
        ("mcxl255", "cmpa"),
        ("mcxn947", "cfpa"),
        ("mcxn947", "cmpa"),
        ("nhs52s04", "cfpa"),
        ("nhs52s04", "cmpa"),
    ],
)
def test_user_config(cli_runner: CliRunner, tmpdir: str, family: str, type: str) -> None:
    """Test PFR CLI generation of user configuration template.

    This test verifies that the PFR CLI can successfully generate a user configuration
    template file and that the generated configuration contains the expected family
    and type values.

    :param cli_runner: Click CLI test runner for invoking CLI commands.
    :param tmpdir: Temporary directory path for output files.
    :param family: Target MCU family name for PFR configuration.
    :param type: PFR configuration type (e.g., CMPA, CFPA).
    """
    cmd = [
        "get-template",
        "--family",
        family,
        "--type",
        type,
        "--output",
        f"{tmpdir}/pfr.yml",
    ]
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd)
    pfr_config = Config.create_from_file(f"{tmpdir}/pfr.yml")
    assert pfr_config
    assert pfr_config["type"] == type.upper()
    assert pfr_config["family"] == family


@pytest.mark.parametrize(
    "test_pass,dfl_niden,dfl_inverse,ignore",
    [
        (True, 0x0, 0xFFFF, False),  # OK
        (False, 0x0, 0xFFFE, False),  # breaking rule 1.4
        (True, 0x0, 0xFFFE, True),  # breaking rule 1.4
        (True, 0x1, 0xFFFE, True),  # breaking rule 1.7
        (False, 0x1, 0xFFFE, False),  # breaking rule 1.7
    ],
)
def test_pfrc_integration_1(
    cli_runner: CliRunner,
    tmp_path: str,
    data_dir: str,
    test_pass: bool,
    dfl_niden: int,
    dfl_inverse: int,
    ignore: bool,
) -> None:
    """Test PFRC integration with configurable NIDEN and INVERSE_VALUE settings.

    This test creates a CMPA configuration file with specified NIDEN and INVERSE_VALUE
    bitfield settings, then runs the pfrc export command to verify proper handling
    of these security configurations.

    :param cli_runner: Click CLI test runner for command execution.
    :param tmp_path: Temporary directory path for test files.
    :param data_dir: Directory containing test data files.
    :param test_pass: Expected test outcome - True for success, False for failure.
    :param dfl_niden: NIDEN bitfield value to set in DCFG_CC_SOCU_DFLT.
    :param dfl_inverse: INVERSE_VALUE bitfield value to set in DCFG_CC_SOCU_DFLT.
    :param ignore: Whether to add --ignore flag to the export command.
    """
    cmpa_config_template = os.path.join(data_dir, "cmpa_lpc55s3x_default.yaml")
    config = load_configuration(cmpa_config_template)
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"]["NIDEN"] = dfl_niden
    config["settings"]["DCFG_CC_SOCU_DFLT"]["bitfields"]["Inverse_value"] = dfl_inverse
    cmpa_config_path = os.path.join(tmp_path, "output.yaml")
    output_bin = os.path.join(tmp_path, "pfr.bin")
    with open(cmpa_config_path, "w") as fp:
        yaml = YAML()
        yaml.dump(config, fp)

    cmd = f"export --config {cmpa_config_path} --output {output_bin}"
    if ignore:
        cmd += " --ignore"
    logging.debug(cmd)
    cli_runner.invoke(cli.main, cmd.split(), expected_code=0 if test_pass else 1)


@pytest.mark.parametrize(
    "secret",
    [
        ("mbi_config_lpc55s3x.yaml"),
        ("mbi_config_lpc55s3x_bin_certblock.yaml"),
        ("cert_block_v21.yaml"),
        ("cert_block_v21.bin"),
    ],
)
def test_generate_cmpa_certblock_lpc55s3x(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, secret: str
) -> None:
    """Test PFR CLI - Generation CMPA binary with elf2sb.

    Test the PFR CLI export command for generating CMPA (Customer Manufacturing Programming Area)
    binary file for LPC55S3x device using elf2sb tool. Verifies that the generated binary matches
    the expected reference file.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    :param secret: Secret/password string for encryption.
    """
    new = f"{tmpdir}/new.bin"
    org = "cmpa_lpc55s3x.bin"
    cmd = f"export --config cmpa_lpc55s3x.json -e {secret} -o {new}"

    with use_working_directory(data_dir):
        logging.debug(cmd)
        cli_runner.invoke(cli.main, cmd.split())
        assert filecmp.cmp(org, new)
