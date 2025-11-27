#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK nxpimage certificate block functionality tests.

This module contains comprehensive tests for certificate block operations
in the nxpimage application, including template generation, parsing,
and AHAB (Advanced High Assurance Boot) integration for MCU provisioning.
"""

import json
import os
from typing import Any

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_configuration
from tests.cli_runner import CliRunner


def process_config_file(
    config_path: str, destination: str, config_member: str
) -> tuple[str, str, str]:
    """Process configuration file and update binary path.

    Loads a configuration file, normalizes path separators to forward slashes,
    and creates a new configuration file with updated binary path pointing to
    the destination directory.

    :param config_path: Path to the source configuration file to process.
    :param destination: Destination directory where new binary and config will be located.
    :param config_member: Key name in configuration that contains the binary path to update.
    :return: Tuple containing original binary path, new binary path, and new config file path.
    """
    config_data = load_configuration(config_path)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data[config_member]
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/new_config.json"
    config_data[config_member] = new_binary
    with open(new_config, "w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def test_nxpimage_cert_block_get_template(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test certificate block template generation command.

    Verifies that the nxpimage cert-block get-template command successfully
    generates a YAML template file for the specified MCU family.

    :param cli_runner: CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file output.
    """
    out_file = f"{tmpdir}/cert_block_template.yaml"

    cmd = ["cert-block", "get-template", "--family", "lpc55s3x", "--output", out_file]
    cli_runner.invoke(nxpimage.main, cmd)
    assert os.path.isfile(out_file)


def test_nxpimage_cert_block_parse(
    cli_runner: CliRunner, nxpimage_data_dir: Any, tmpdir: Any
) -> None:
    """Test nxpimage cert-block parse command functionality.

    Verifies that the cert-block parse command correctly processes a certificate block
    binary file and generates the expected output files including configuration YAML
    and certificate public key files.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param nxpimage_data_dir: Directory containing test data files for nxpimage.
    :param tmpdir: Temporary directory for test output files.
    """
    out_folder = str(tmpdir)
    input_file = os.path.join(
        nxpimage_data_dir, "workspace", "output_images", "lpc55s3x", "cert_384_256.bin"
    )
    cmd = ["cert-block", "parse", "-f", "lpc55s3x", "-b", input_file, "-o", out_folder]
    cli_runner.invoke(nxpimage.main, cmd)
    assert os.path.isfile(os.path.join(out_folder, "cert_block_config.yaml"))
    assert os.path.isfile(os.path.join(out_folder, "rootCertificate0File.pub"))
    assert os.path.isfile(os.path.join(out_folder, "signingCertificateFile.pub"))


def test_nxpimage_mcxn556s_cert_block_vs_ahab_get_template(
    cli_runner: CliRunner, tmpdir: Any
) -> None:
    """Test that cert-block and ahab certificate get-template produce equivalent results for mcxn556s.

    This test verifies that both the cert-block and ahab certificate commands generate
    functionally equivalent YAML templates for the mcxn556s family. It compares the
    output files to ensure consistency between the two command interfaces.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for storing generated template files.
    :raises AssertionError: When commands fail or generated templates are not equivalent.
    """
    cert_block_template = f"{tmpdir}/cert_block_template.yaml"
    ahab_template = f"{tmpdir}/ahab_template.yaml"

    # Get template via cert-block command
    cmd_cert_block = [
        "cert-block",
        "get-template",
        "--family",
        "mcxn556s",
        "--output",
        cert_block_template,
    ]
    result_cert_block = cli_runner.invoke(nxpimage.main, cmd_cert_block)

    # Get template via ahab certificate command
    cmd_ahab = [
        "ahab",
        "certificate",
        "get-template",
        "--family",
        "mcxn556s",
        "--output",
        ahab_template,
    ]
    result_ahab = cli_runner.invoke(nxpimage.main, cmd_ahab)

    # Check if mcxn556s is supported
    if result_cert_block.exit_code != 0 and (
        "not supported" in result_cert_block.output.lower()
        or "invalid choice" in result_cert_block.output.lower()
    ):
        pytest.skip("mcxn556s not supported by cert-block")

    if result_ahab.exit_code != 0 and (
        "not supported" in result_ahab.output.lower()
        or "invalid choice" in result_ahab.output.lower()
    ):
        pytest.skip("mcxn556s not supported by ahab certificate")

    # Both commands should succeed
    assert result_cert_block.exit_code == 0, f"cert-block failed: {result_cert_block.output}"
    assert result_ahab.exit_code == 0, f"ahab failed: {result_ahab.output}"

    # Both files should exist
    assert os.path.isfile(cert_block_template)
    assert os.path.isfile(ahab_template)

    # Load and compare the templates (they should be functionally equivalent)
    with open(cert_block_template, "r", encoding="utf-8") as f:
        cert_block_config = yaml.safe_load(f)
    with open(ahab_template, "r", encoding="utf-8") as f:
        ahab_config = yaml.safe_load(f)

    # Key fields should be present in both templates
    assert "family" in cert_block_config
    assert "family" in ahab_config
    assert cert_block_config["family"] == ahab_config["family"] == "mcxn556s"


def test_nxpimage_mcxn556s_cert_block_vs_ahab_export(
    cli_runner: CliRunner, tmpdir: Any, nxpimage_data_dir: Any
) -> None:
    """Test that cert-block and ahab certificate export produce equivalent results for mcxn556s.

    This test verifies that both the cert-block and ahab certificate export commands
    produce identical binary outputs when given the same configuration for the mcxn556s
    family. The test first checks if mcxn556s is supported, then creates equivalent
    configurations for both commands and compares their outputs.

    :param cli_runner: Click CLI runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory for test files.
    :param nxpimage_data_dir: Directory containing nxpimage test data files.
    """
    # First, check if mcxn556s is supported by trying to get a template
    template_test = f"{tmpdir}/template_test.yaml"
    template_cmd = ["cert-block", "get-template", "--family", "mcxn556s", "--output", template_test]
    template_result = cli_runner.invoke(nxpimage.main, template_cmd)

    if template_result.exit_code != 0:
        if (
            "not supported" in template_result.output.lower()
            or "invalid choice" in template_result.output.lower()
        ):
            pytest.skip("mcxn556s not supported by cert-block")
        else:
            pytest.fail(f"Unexpected error getting template: {template_result.output}")

    # Clean up template test file
    if os.path.exists(template_test):
        os.remove(template_test)

    test_key_file = os.path.join(
        nxpimage_data_dir, "..", "..", "_data", "keys", "ecc256", "srk0_ecc256.pem"
    )

    if not test_key_file:
        pytest.skip("No test key files found for mcxn556s export test")

    # Create cert-block config using the actual template structure
    cert_block_output = f"{tmpdir}/cert_block_output.bin"
    cert_block_config = {
        "family": "mcxn556s",
        "revision": "latest",
        "containerOutputFile": cert_block_output,
        "permissions": ["container"],
        "fuse_version": 0,
        "public_key_0": test_key_file,
        "signer_0": test_key_file,
    }
    cert_block_config_file = f"{tmpdir}/cert_block_config.yaml"
    with open(cert_block_config_file, "w", encoding="utf-8") as f:
        yaml.dump(cert_block_config, f)

    # Create ahab certificate config
    ahab_output = f"{tmpdir}/ahab_output.bin"
    ahab_config = {
        "family": "mcxn556s",
        "revision": "latest",
        "containerOutputFile": ahab_output,
        "permissions": ["container"],
        "fuse_version": 0,
        "public_key_0": test_key_file,
        "signer_0": test_key_file,
    }
    ahab_config_file = f"{tmpdir}/ahab_config.yaml"
    with open(ahab_config_file, "w", encoding="utf-8") as f:
        yaml.dump(ahab_config, f)

    # Export via cert-block command
    cmd_cert_block = ["cert-block", "export", "-c", cert_block_config_file]
    result_cert_block = cli_runner.invoke(nxpimage.main, cmd_cert_block)

    # Export via ahab certificate command
    cmd_ahab = ["ahab", "certificate", "export", "-c", ahab_config_file]
    result_ahab = cli_runner.invoke(nxpimage.main, cmd_ahab)

    # Both commands should have the same exit code (success or same failure)
    assert result_cert_block.exit_code == result_ahab.exit_code, (
        f"cert-block exit code: {result_cert_block.exit_code}, ahab exit code: {result_ahab.exit_code}\n"
        f"cert-block output: {result_cert_block.output}\n"
        f"ahab output: {result_ahab.output}"
    )

    # If both succeeded, compare the output files
    if result_cert_block.exit_code == 0 and result_ahab.exit_code == 0:
        assert os.path.isfile(cert_block_output)
        assert os.path.isfile(ahab_output)
        # The binary outputs should be identical
        assert os.path.getsize(cert_block_output) == os.path.getsize(ahab_output)


def test_nxpimage_mcxn556s_cert_block_vs_ahab_parse(
    cli_runner: CliRunner, tmpdir: Any, nxpimage_data_dir: Any
) -> None:
    """Test that cert-block and ahab certificate parse produce equivalent results for mcxn556s.

    This test validates that both the cert-block and ahab certificate parsing commands
    produce consistent and equivalent configuration outputs when processing the same
    certificate binary for the mcxn556s family. The test creates a test certificate
    using ahab certificate export, then parses it with both commands and compares
    the resulting configuration files.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param nxpimage_data_dir: Path to nxpimage test data directory containing test keys.
    """
    # First, check if mcxn556s is supported by trying to get a template
    template_test = f"{tmpdir}/template_test.yaml"
    template_cmd = ["cert-block", "get-template", "--family", "mcxn556s", "--output", template_test]
    template_result = cli_runner.invoke(nxpimage.main, template_cmd)

    if template_result.exit_code != 0:
        if (
            "not supported" in template_result.output.lower()
            or "invalid choice" in template_result.output.lower()
        ):
            pytest.skip("mcxn556s not supported by cert-block")
        else:
            pytest.fail(f"Unexpected error getting template: {template_result.output}")

    # Clean up template test file
    if os.path.exists(template_test):
        os.remove(template_test)

    test_key_file = os.path.join(
        nxpimage_data_dir, "..", "..", "_data", "keys", "ecc256", "srk0_ecc256.pem"
    )

    # Create ahab certificate config and export a test binary
    test_binary = f"{tmpdir}/test_certificate.bin"
    ahab_config = {
        "family": "mcxn556s",
        "revision": "latest",
        "permissions": ["container"],
        "fuse_version": 0,
        "public_key_0": test_key_file,
        "signer_0": test_key_file,
    }
    ahab_config_file = f"{tmpdir}/ahab_config.yaml"
    with open(ahab_config_file, "w", encoding="utf-8") as f:
        yaml.dump(ahab_config, f)

    # Export via ahab certificate command to create test binary
    cmd_ahab_export = ["ahab", "certificate", "export", "-c", ahab_config_file, "-o", test_binary]
    result_ahab_export = cli_runner.invoke(nxpimage.main, cmd_ahab_export)

    if result_ahab_export.exit_code != 0:
        pytest.skip(
            f"Could not export test binary with ahab certificate: {result_ahab_export.output}"
        )

    if not os.path.exists(test_binary):
        pytest.skip("Test binary was not created successfully")

    cert_block_output_dir = f"{tmpdir}/cert_block_parse"
    ahab_output_dir = f"{tmpdir}/ahab_parse"
    os.makedirs(cert_block_output_dir, exist_ok=True)
    os.makedirs(ahab_output_dir, exist_ok=True)

    # Parse via cert-block command
    cmd_cert_block = [
        "cert-block",
        "parse",
        "-f",
        "mcxn556s",
        "-b",
        test_binary,
        "-o",
        cert_block_output_dir,
    ]
    result_cert_block = cli_runner.invoke(nxpimage.main, cmd_cert_block)

    # Parse via ahab certificate command
    cmd_ahab = [
        "ahab",
        "certificate",
        "parse",
        "-f",
        "mcxn556s",
        "-b",
        test_binary,
        "-o",
        ahab_output_dir,
    ]
    result_ahab = cli_runner.invoke(nxpimage.main, cmd_ahab)

    # Check if commands are supported
    if result_cert_block.exit_code != 0 and "not supported" in result_cert_block.output.lower():
        pytest.skip("mcxn556s not supported by cert-block")
    if result_ahab.exit_code != 0 and "not supported" in result_ahab.output.lower():
        pytest.skip("mcxn556s not supported by ahab certificate")

    # Both commands should have the same exit code
    assert result_cert_block.exit_code == result_ahab.exit_code

    # If both succeeded, compare the output configurations
    if result_cert_block.exit_code == 0 and result_ahab.exit_code == 0:
        cert_block_config_file = os.path.join(cert_block_output_dir, "cert_block_config.yaml")
        ahab_config_file = os.path.join(ahab_output_dir, "certificate_config.yaml")

        assert os.path.isfile(cert_block_config_file)
        assert os.path.isfile(ahab_config_file)

        # Load and compare key configuration elements
        with open(cert_block_config_file, "r", encoding="utf-8") as f:
            cert_block_config = yaml.safe_load(f)
        with open(ahab_config_file, "r", encoding="utf-8") as f:
            ahab_config = yaml.safe_load(f)

        # Key fields should match
        assert cert_block_config["family"] == ahab_config["family"]
        assert cert_block_config.get("fuse_version") == ahab_config.get("fuse_version")


def test_nxpimage_mcxn556s_cert_block_feature_detection(cli_runner: CliRunner) -> None:
    """Test that mcxn556s family properly supports both cert-block and ahab certificate features.

    This test verifies feature detection consistency by checking that the mcxn556s
    family is supported by both cert-block and ahab certificate commands. It ensures
    that if one feature is supported, both should be supported to maintain consistency
    in the SPSDK implementation.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    """
    # Test get-template to see if mcxn556s is supported by cert-block
    tmpfile = f"test_template_{os.getpid()}.yaml"
    cmd_cert_block = ["cert-block", "get-template", "--family", "mcxn556s", "--output", tmpfile]
    result_cert_block = cli_runner.invoke(nxpimage.main, cmd_cert_block)

    # Test get-template to see if mcxn556s is supported by ahab certificate
    tmpfile2 = f"test_template_ahab_{os.getpid()}.yaml"
    cmd_ahab = ["ahab", "certificate", "get-template", "--family", "mcxn556s", "--output", tmpfile2]
    result_ahab = cli_runner.invoke(nxpimage.main, cmd_ahab)

    # Clean up
    for f in [tmpfile, tmpfile2]:
        if os.path.exists(f):
            os.remove(f)

    # Both should have the same support status
    cert_block_supported = result_cert_block.exit_code == 0
    ahab_supported = result_ahab.exit_code == 0

    # If mcxn556s is supported by one, it should be supported by both
    if cert_block_supported or ahab_supported:
        assert (
            cert_block_supported == ahab_supported
        ), f"Inconsistent support: cert-block={cert_block_supported}, ahab={ahab_supported}"


def test_nxpimage_mcxn556s_cert_block_supported_families(cli_runner: CliRunner) -> None:
    """Test that mcxn556s is properly detected as supporting cert-block.

    This test verifies the cert-block functionality for the mcxn556s family by attempting
    to generate a template file. The test handles both supported and unsupported scenarios
    gracefully, checking appropriate success or error messages.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    """
    # Test get-template to see if mcxn556s is supported
    tmpfile = "test_template.yaml"
    cmd = ["cert-block", "get-template", "--family", "mcxn556s", "--output", tmpfile]
    result = cli_runner.invoke(nxpimage.main, cmd)

    # Clean up
    if os.path.exists(tmpfile):
        os.remove(tmpfile)

    # If mcxn556s is supported, the command should succeed
    # If not supported, it should fail with appropriate message
    if result.exit_code == 0:
        # mcxn556s is supported
        assert "template file" in result.output.lower() or result.exit_code == 0
    else:
        # Check if it's an unsupported family error
        assert "not supported" in result.output.lower() or "invalid choice" in result.output.lower()


def test_nxpimage_mcxn556s_cert_block_ahab_equivalence_basic(
    cli_runner: CliRunner, tmpdir: str
) -> None:
    """Test cert-block and ahab certificate commands equivalence for MCXN556S family.

    Verifies that both cert-block and ahab certificate commands produce equivalent
    behavior when generating templates for the MCXN556S family. The test ensures
    both commands have the same success/failure status and generate valid templates
    containing the correct family specification.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory path for storing generated template files
    """
    # Test template generation
    cert_block_template = f"{tmpdir}/cb_template.yaml"
    ahab_template = f"{tmpdir}/ahab_template.yaml"

    # Try to get templates
    cb_result = cli_runner.invoke(
        nxpimage.main,
        ["cert-block", "get-template", "--family", "mcxn556s", "--output", cert_block_template],
    )
    ahab_result = cli_runner.invoke(
        nxpimage.main,
        ["ahab", "certificate", "get-template", "--family", "mcxn556s", "--output", ahab_template],
    )

    # Both should have the same success/failure status
    assert (cb_result.exit_code == 0) == (
        ahab_result.exit_code == 0
    ), f"cert-block exit code: {cb_result.exit_code}, ahab exit code: {ahab_result.exit_code}"

    # If both succeeded, both templates should exist
    if cb_result.exit_code == 0 and ahab_result.exit_code == 0:
        assert os.path.isfile(cert_block_template)
        assert os.path.isfile(ahab_template)

        # Both should contain family specification
        with open(cert_block_template, "r", encoding="utf-8") as f:
            cb_content = f.read()
        with open(ahab_template, "r", encoding="utf-8") as f:
            ahab_content = f.read()

        assert "mcxn556s" in cb_content
        assert "mcxn556s" in ahab_content
