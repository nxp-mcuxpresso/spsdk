#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Extended pytest tests for pfr CLI application.

Tests cover all pfr commands using --help invocations and hardware-free
operations (get-families, get-template, get-templates) to maximize code
coverage without requiring real MCU hardware.
"""

import os

import pytest

from spsdk.apps.pfr import main
from spsdk.pfr.pfr import CONFIG_AREA_CLASSES
from tests.cli_runner import CliRunner

# Family that supports both cmpa and cfpa without hardware
PFR_FAMILY = "lpc55s69"

ALL_AREA_TYPES = sorted(CONFIG_AREA_CLASSES.keys())


# ---------------------------------------------------------------------------
# Top-level help
# ---------------------------------------------------------------------------


def test_pfr_help(cli_runner: CliRunner) -> None:
    """Test top-level pfr --help output."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# All commands via --help
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "get-template",
        "get-templates",
        "parse",
        "export",
        "write",
        "read",
        "erase-cmpa",
    ],
)
def test_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each pfr command responds to --help."""
    result = cli_runner.invoke(main, [command, "--help"])
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# get-families (hardware-free)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cmd_name",
    [
        "get-template",
        "get-templates",
        "parse",
        "write",
        "read",
        "erase-cmpa",
    ],
)
def test_get_families(cli_runner: CliRunner, cmd_name: str) -> None:
    """Test get-families lists supported families for each sub-command."""
    result = cli_runner.invoke(main, ["get-families", "-c", cmd_name])
    assert result.output


# ---------------------------------------------------------------------------
# get-template (hardware-free)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("area_type", ["cmpa", "cfpa"])
def test_get_template(cli_runner: CliRunner, tmp_path: str, area_type: str) -> None:
    """Test get-template generates a YAML template file for lpc55s69."""
    output_file = os.path.join(str(tmp_path), f"{area_type}_template.yaml")
    cli_runner.invoke(
        main,
        ["get-template", "-f", PFR_FAMILY, "-t", area_type, "-o", output_file],
    )
    assert os.path.isfile(output_file), f"Template file not created: {output_file}"
    with open(output_file) as f:
        content = f.read()
    assert len(content) > 0


def test_get_template_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test get-template with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["get-template"], expected_code=-1)
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# get-templates (hardware-free)
# ---------------------------------------------------------------------------


def test_get_templates(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test get-templates generates YAML templates for all areas of a family."""
    output_dir = str(tmp_path)
    cli_runner.invoke(
        main,
        ["get-templates", "-f", PFR_FAMILY, "-o", output_dir],
    )
    # At least one YAML file should be created
    yaml_files = [f for f in os.listdir(output_dir) if f.endswith(".yaml")]
    assert len(yaml_files) > 0, "No YAML template files were generated"


def test_get_templates_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test get-templates with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["get-templates"], expected_code=-1)
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# parse (hardware-free, requires binary file)
# ---------------------------------------------------------------------------


def test_parse_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test parse with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["parse"], expected_code=-1)
    assert result.exit_code != 0


def test_parse_missing_binary(cli_runner: CliRunner) -> None:
    """Test parse fails when binary file does not exist."""
    result = cli_runner.invoke(
        main,
        ["parse", "-f", PFR_FAMILY, "-t", "cmpa", "-b", "nonexistent.bin"],
        expected_code=-1,
    )
    assert result.exit_code != 0


def test_parse_binary(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test parse with a minimal binary (all zeros)."""
    from spsdk.pfr.pfr import CMPA
    from spsdk.utils.family import FamilyRevision

    family = FamilyRevision("lpc55s69")
    cmpa = CMPA(family=family)
    binary = cmpa.export()
    bin_path = os.path.join(str(tmp_path), "cmpa.bin")
    with open(bin_path, "wb") as f:
        f.write(binary)

    out_path = os.path.join(str(tmp_path), "parsed.yaml")
    cli_runner.invoke(
        main,
        ["parse", "-f", PFR_FAMILY, "-t", "cmpa", "-b", bin_path, "-o", out_path],
    )
    assert os.path.isfile(out_path)


def test_parse_binary_show_diff(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test parse with --show-diff flag."""
    from spsdk.pfr.pfr import CMPA
    from spsdk.utils.family import FamilyRevision

    family = FamilyRevision("lpc55s69")
    cmpa = CMPA(family=family)
    binary = cmpa.export()
    bin_path = os.path.join(str(tmp_path), "cmpa.bin")
    with open(bin_path, "wb") as f:
        f.write(binary)

    out_path = os.path.join(str(tmp_path), "parsed_diff.yaml")
    result = cli_runner.invoke(
        main,
        ["parse", "-f", PFR_FAMILY, "-t", "cmpa", "-b", bin_path, "-o", out_path, "--show-diff"],
    )
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# export (hardware-free with valid config)
# ---------------------------------------------------------------------------


def test_export_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test export with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["export"], expected_code=-1)
    assert result.exit_code != 0


def test_export_missing_config(cli_runner: CliRunner) -> None:
    """Test export fails when config file does not exist."""
    result = cli_runner.invoke(
        main,
        ["export", "--config", "nonexistent_config.yaml", "--output", "out.bin"],
        expected_code=-1,
    )
    assert result.exit_code != 0


def test_export_from_template(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test export using a generated template as config."""
    template_file = os.path.join(str(tmp_path), "cmpa_template.yaml")
    output_bin = os.path.join(str(tmp_path), "cmpa.bin")

    # Generate template first
    cli_runner.invoke(
        main,
        ["get-template", "-f", PFR_FAMILY, "-t", "cmpa", "-o", template_file],
    )
    assert os.path.isfile(template_file)

    # Export binary from template
    cli_runner.invoke(
        main,
        ["export", "--config", template_file, "--output", output_bin, "--ignore"],
    )
    assert os.path.isfile(output_bin)
    with open(output_bin, "rb") as f:
        data = f.read()
    assert len(data) > 0


def test_export_with_add_seal(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test export with --add-seal flag."""
    template_file = os.path.join(str(tmp_path), "cfpa_template.yaml")
    output_bin = os.path.join(str(tmp_path), "cfpa.bin")

    cli_runner.invoke(
        main,
        ["get-template", "-f", PFR_FAMILY, "-t", "cfpa", "-o", template_file],
    )
    assert os.path.isfile(template_file)

    cli_runner.invoke(
        main,
        ["export", "--config", template_file, "--output", output_bin, "--add-seal", "--ignore"],
    )
    assert os.path.isfile(output_bin)


# ---------------------------------------------------------------------------
# write (hardware required — test --help and error paths only)
# ---------------------------------------------------------------------------


def test_write_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test write with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["write"], expected_code=-1)
    assert result.exit_code != 0


def test_write_missing_interface(cli_runner: CliRunner) -> None:
    """Test write fails without a hardware interface."""
    result = cli_runner.invoke(
        main,
        ["write", "-f", PFR_FAMILY, "-t", "cmpa", "--binary", "some.bin"],
        expected_code=-1,
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# read (hardware required — test --help and error paths only)
# ---------------------------------------------------------------------------


def test_read_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test read with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["read"], expected_code=-1)
    assert result.exit_code != 0


def test_read_missing_interface(cli_runner: CliRunner) -> None:
    """Test read fails without a hardware interface."""
    result = cli_runner.invoke(
        main,
        ["read", "-f", PFR_FAMILY, "-t", "cmpa"],
        expected_code=-1,
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# erase-cmpa (hardware required — test --help and error paths only)
# ---------------------------------------------------------------------------


def test_erase_cmpa_no_args_is_help(cli_runner: CliRunner) -> None:
    """Test erase-cmpa with no args exits non-zero (no_args_is_help behaviour)."""
    result = cli_runner.invoke(main, ["erase-cmpa"], expected_code=-1)
    assert result.exit_code != 0


def test_erase_cmpa_missing_interface(cli_runner: CliRunner) -> None:
    """Test erase-cmpa fails without a hardware interface."""
    result = cli_runner.invoke(
        main,
        ["erase-cmpa", "-f", PFR_FAMILY],
        expected_code=-1,
    )
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Multiple families for get-template
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "family,area_type",
    [
        ("lpc55s69", "cmpa"),
        ("lpc55s69", "cfpa"),
        ("lpc55s3x", "cmpa"),
        ("lpc55s3x", "cfpa"),
        ("mcxn9xx", "cmpa"),
        ("mcxn9xx", "cfpa"),
    ],
)
def test_get_template_multiple_families(
    cli_runner: CliRunner, tmp_path: str, family: str, area_type: str
) -> None:
    """Test get-template generates templates for multiple families and area types."""
    output_file = os.path.join(str(tmp_path), f"{family}_{area_type}.yaml")
    cli_runner.invoke(
        main,
        ["get-template", "-f", family, "-t", area_type, "-o", output_file],
    )
    assert os.path.isfile(output_file), f"Template not created for {family}/{area_type}"
