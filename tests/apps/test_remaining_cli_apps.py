#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Pytest tests for 5 remaining SPSDK CLI apps: nxpdevhsm, nxpshe, lpcprog, nxpwpc, nxpuuu.

Tests cover --help for every command, hardware-free commands (get-families),
and get-template with a supported family to maximize coverage without real hardware.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from spsdk.apps.lpcprog import main as lpcprog_main
from spsdk.apps.nxpdevhsm import main as nxpdevhsm_main
from spsdk.apps.nxpshe import main as nxpshe_main
from spsdk.apps.nxpuuu import main as nxpuuu_main
from spsdk.apps.nxpwpc import main as nxpwpc_main
from tests.cli_runner import CliRunner

# ---------------------------------------------------------------------------
# nxpdevhsm
# ---------------------------------------------------------------------------


def test_nxpdevhsm_help(cli_runner: CliRunner) -> None:
    """Test top-level --help."""
    result = cli_runner.invoke(nxpdevhsm_main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "command",
    [
        "generate",
        "get-template",
        "get-families",
        "gen-master-share",
        "set-master-share",
        "wrap-cust-mk-sk",
        "get-cust-fw-auth",
    ],
)
def test_nxpdevhsm_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each nxpdevhsm command responds to --help."""
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(nxpdevhsm_main, args)
    assert "Show this message and exit." in result.output


def test_nxpdevhsm_get_families(cli_runner: CliRunner) -> None:
    """Test get-families (no hardware required)."""
    result = cli_runner.invoke(nxpdevhsm_main, ["get-families"])
    assert result.exit_code == 0


def test_nxpdevhsm_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test get-template with a supported family."""
    from spsdk.apps.nxpdevhsm import DevHsm

    family = DevHsm.get_supported_families()[0].name
    out = str(tmp_path / "devhsm_template.yaml")
    result = cli_runner.invoke(nxpdevhsm_main, ["get-template", "-f", family, "-o", out])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# nxpshe
# ---------------------------------------------------------------------------


def test_nxpshe_help(cli_runner: CliRunner) -> None:
    """Test top-level --help."""
    result = cli_runner.invoke(nxpshe_main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "command",
    [
        "get-template",
        "get-families",
        "update",
        "verify",
        "calc-boot-mac",
        "set-boot-mode",
        "derive-key",
        "setup",
        "reset",
    ],
)
def test_nxpshe_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each nxpshe command responds to --help."""
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(nxpshe_main, args)
    assert "Show this message and exit." in result.output


def test_nxpshe_get_families(cli_runner: CliRunner) -> None:
    """Test get-families (no hardware required)."""
    result = cli_runner.invoke(nxpshe_main, ["get-families"])
    assert result.exit_code == 0


def test_nxpshe_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test get-template with a supported family."""
    from spsdk.apps.nxpshe import SHEUpdate

    family = SHEUpdate.get_supported_families()[0].name
    out = str(tmp_path / "she_template.yaml")
    result = cli_runner.invoke(nxpshe_main, ["get-template", "-f", family, "-o", out])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# lpcprog
# ---------------------------------------------------------------------------


def test_lpcprog_help(cli_runner: CliRunner) -> None:
    """Test top-level --help."""
    result = cli_runner.invoke(lpcprog_main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "command",
    [
        "get-families",
        "read-memory",
        "erase-sector",
        "erase-page",
        "unlock",
        "set-baud-rate",
        "set-echo",
        "write-ram",
        "sync",
        "get-info",
        "prepare-sectors",
        "go",
        "program-flash",
        "compare",
        "blank-check-sectors",
        "read-flash-signature",
        "read-crc-checksum",
    ],
)
def test_lpcprog_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each lpcprog command responds to --help."""
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(lpcprog_main, args)
    assert "Show this message and exit." in result.output


def test_lpcprog_get_families(cli_runner: CliRunner) -> None:
    """Test get-families — lpcprog requires -f at group level; patch sys.argv so is_click_help skips port."""
    from spsdk.apps.lpcprog import LPCProgProtocol

    family = LPCProgProtocol.get_supported_families()[0].name
    args = ["-f", family, "get-families"]
    with patch.object(sys, "argv", ["lpcprog"] + args):
        result = cli_runner.invoke(lpcprog_main, args)
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# nxpwpc
# ---------------------------------------------------------------------------


def test_nxpwpc_help(cli_runner: CliRunner) -> None:
    """Test top-level --help."""
    result = cli_runner.invoke(nxpwpc_main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "command",
    [
        "insert-cert",
        "get-id",
        "get-cert",
        "put-cert",
        "get-template",
        "get-families",
    ],
)
def test_nxpwpc_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each nxpwpc command responds to --help."""
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(nxpwpc_main, args)
    assert "Show this message and exit." in result.output


def test_nxpwpc_get_families(cli_runner: CliRunner) -> None:
    """Test get-families (no hardware required)."""
    result = cli_runner.invoke(nxpwpc_main, ["get-families"])
    assert result.exit_code == 0


def test_nxpwpc_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test get-template with a supported family, service type, and target type."""
    from spsdk.apps.nxpwpc import WPC

    family = WPC.get_supported_families()[0].name
    service_type = list(WPC.SERVICES.keys())[0]
    target_type = list(WPC.TARGETS.keys())[0]
    out = str(tmp_path / "wpc_template.yaml")
    result = cli_runner.invoke(
        nxpwpc_main,
        [
            "get-template",
            "-f",
            family,
            "-st",
            service_type,
            "-tt",
            target_type,
            "-o",
            out,
        ],
    )
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# nxpuuu
# ---------------------------------------------------------------------------


def test_nxpuuu_help(cli_runner: CliRunner) -> None:
    """Test top-level --help."""
    result = cli_runner.invoke(nxpuuu_main, ["--help"])
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "command",
    [
        "run",
        "script",
        "write",
        "get-families",
        "list-devices",
        "udev",
    ],
)
def test_nxpuuu_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each nxpuuu command responds to --help."""
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(nxpuuu_main, args)
    assert "Show this message and exit." in result.output


def test_nxpuuu_get_families(cli_runner: CliRunner) -> None:
    """Test get-families (no hardware required)."""
    result = cli_runner.invoke(nxpuuu_main, ["get-families"])
    assert result.exit_code == 0
