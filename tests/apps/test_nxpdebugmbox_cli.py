#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Comprehensive pytest tests for nxpdebugmbox CLI application.

Tests cover all command groups and subcommands using --help invocations and
hardware-free subcommands (get-families, get-template, etc.) to maximize
code coverage without requiring real debug probe hardware.
"""

import os

import pytest

from spsdk.apps.nxpdebugmbox import main
from tests.cli_runner import CliRunner

# Family used for hardware-free template/family tests
DAT_FAMILY = "lpc55s69"


# ---------------------------------------------------------------------------
# Top-level tests
# ---------------------------------------------------------------------------


def test_nxpdebugmbox_help(cli_runner: CliRunner) -> None:
    """Test top-level --help output."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


def test_nxpdebugmbox_get_families(cli_runner: CliRunner) -> None:
    """Test top-level get-families command."""
    result = cli_runner.invoke(main, ["get-families"])
    assert result.output  # Should list supported families


# ---------------------------------------------------------------------------
# famode-image group
# ---------------------------------------------------------------------------


def test_famode_image_help(cli_runner: CliRunner) -> None:
    """Test famode-image group --help."""
    result = cli_runner.invoke(main, ["famode-image", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    ["export", "parse", "get-templates"],
)
def test_famode_image_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test famode-image subcommand --help outputs."""
    result = cli_runner.invoke(main, ["famode-image", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_famode_image_get_families(cli_runner: CliRunner) -> None:
    """Test famode-image get-families lists supported families."""
    result = cli_runner.invoke(main, ["famode-image", "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# dat group
# ---------------------------------------------------------------------------


def test_dat_help(cli_runner: CliRunner) -> None:
    """Test dat group --help."""
    result = cli_runner.invoke(main, ["dat", "--help"])
    assert "Show this message and exit." in result.output


def test_dat_auth_help(cli_runner: CliRunner) -> None:
    """Test dat auth --help."""
    result = cli_runner.invoke(main, ["dat", "auth", "--help"])
    assert "Show this message and exit." in result.output


def test_dat_auth_missing_file_fails(cli_runner: CliRunner) -> None:
    """Test dat auth with a missing config file returns non-zero exit code."""
    cli_runner.invoke(
        main,
        ["dat", "auth", "--config", "/nonexistent/path/dat_auth.yaml"],
        expected_code=-1,
    )


def test_dat_get_template(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test dat get-template generates YAML template without hardware."""
    out_file = os.path.join(str(tmp_path), "dat_template.yaml")
    cli_runner.invoke(
        main,
        ["dat", "get-template", "--family", DAT_FAMILY, "-o", out_file],
    )
    assert os.path.isfile(out_file)


def test_dat_get_template_help(cli_runner: CliRunner) -> None:
    """Test dat get-template --help."""
    result = cli_runner.invoke(main, ["dat", "get-template", "--help"])
    assert "Show this message and exit." in result.output


def test_dat_get_families(cli_runner: CliRunner) -> None:
    """Test dat get-families lists supported families."""
    result = cli_runner.invoke(main, ["dat", "get-families"])
    assert result.output


# dat dc sub-group
def test_dat_dc_help(cli_runner: CliRunner) -> None:
    """Test dat dc group --help."""
    result = cli_runner.invoke(main, ["dat", "dc", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize("subcommand", ["export", "get-template"])
def test_dat_dc_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test dat dc subcommand --help."""
    result = cli_runner.invoke(main, ["dat", "dc", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_dat_dc_get_families(cli_runner: CliRunner) -> None:
    """Test dat dc get-families lists supported families."""
    result = cli_runner.invoke(main, ["dat", "dc", "get-families"])
    assert result.output


def test_dat_dc_get_template(cli_runner: CliRunner, tmp_path: str) -> None:
    """Test dat dc get-template generates a template YAML."""
    out_file = os.path.join(str(tmp_path), "dc_template.yaml")
    cli_runner.invoke(
        main,
        ["dat", "dc", "get-template", "--family", DAT_FAMILY, "-o", out_file],
    )
    assert os.path.isfile(out_file)


# ---------------------------------------------------------------------------
# mem-tool group
# ---------------------------------------------------------------------------


def test_mem_tool_help(cli_runner: CliRunner) -> None:
    """Test mem-tool group --help."""
    result = cli_runner.invoke(main, ["mem-tool", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize("subcommand", ["read-memory", "write-memory", "test-connection"])
def test_mem_tool_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test mem-tool subcommand --help."""
    result = cli_runner.invoke(main, ["mem-tool", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_mem_tool_get_families(cli_runner: CliRunner) -> None:
    """Test mem-tool get-families lists supported families."""
    result = cli_runner.invoke(main, ["mem-tool", "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# tool group
# ---------------------------------------------------------------------------


def test_tool_help(cli_runner: CliRunner) -> None:
    """Test tool group --help."""
    result = cli_runner.invoke(main, ["tool", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize("subcommand", ["reset", "get-uuid", "halt", "resume"])
def test_tool_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test tool subcommand --help."""
    result = cli_runner.invoke(main, ["tool", subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_tool_get_families(cli_runner: CliRunner) -> None:
    """Test tool get-families lists supported families."""
    result = cli_runner.invoke(main, ["tool", "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# sda group
# ---------------------------------------------------------------------------


def test_sda_help(cli_runner: CliRunner) -> None:
    """Test sda group --help."""
    result = cli_runner.invoke(main, ["sda", "--help"])
    assert "Show this message and exit." in result.output


def test_sda_auth_help(cli_runner: CliRunner) -> None:
    """Test sda auth --help."""
    result = cli_runner.invoke(main, ["sda", "auth", "--help"])
    assert "Show this message and exit." in result.output


def test_sda_get_families(cli_runner: CliRunner) -> None:
    """Test sda get-families lists supported families."""
    result = cli_runner.invoke(main, ["sda", "get-families"])
    assert result.output


# ---------------------------------------------------------------------------
# cmd group
# ---------------------------------------------------------------------------


def test_cmd_help(cli_runner: CliRunner) -> None:
    """Test cmd group --help."""
    result = cli_runner.invoke(main, ["cmd", "--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    [
        "start",
        "exit",
        "erase",
        "famode",
        "ispmode",
        "token-auth",
        "get-crp",
        "start-debug-session",
        "erase-one-sector",
        "write-to-flash",
        "get-dac",
        "send-dar",
        "set-bricked-mode",
        "nxp-ssf-insert-duk",
        "nxp-exec-prov-fw",
        "nxp-ssf-insert-cert",
        "password-auth",
    ],
)
def test_cmd_subcommands_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test cmd subcommand --help (requires -f family before subcommand name)."""
    result = cli_runner.invoke(main, ["cmd", "-f", DAT_FAMILY, subcommand, "--help"])
    assert "Show this message and exit." in result.output


def test_cmd_get_families(cli_runner: CliRunner) -> None:
    """Test cmd get-families lists supported families."""
    result = cli_runner.invoke(main, ["cmd", "-f", DAT_FAMILY, "get-families"])
    assert result.output
