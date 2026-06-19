#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Comprehensive pytest tests for blhost CLI application.

Tests cover all commands and subcommands using --help invocations and
hardware-free commands (get-families) to maximize code coverage without
requiring real MCU hardware.

Note: blhost's spsdk_mboot_interface decorator checks sys.argv for '--help'
to skip the hardware interface requirement. Tests must patch sys.argv accordingly.
"""

import sys
from unittest.mock import patch

import pytest

from spsdk.apps.blhost import main
from tests.cli_runner import CliRunner

# ---------------------------------------------------------------------------
# Top-level help
# ---------------------------------------------------------------------------


def test_blhost_help(cli_runner: CliRunner) -> None:
    """Test top-level --help output."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# All top-level commands via --help (hardware-free via sys.argv patch)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "batch",
        "call",
        "configure-memory",
        "efuse-program-once",
        "efuse-read-once",
        "execute",
        "flash-erase-region",
        "flash-erase-all",
        "flash-erase-all-unsecure",
        "flash-image",
        "flash-program-once",
        "flash-read-once",
        "flash-security-disable",
        "flash-read-resource",
        "fill-memory",
        "fuse-program",
        "fuse-read",
        "list-memory",
        "load-image",
        "get-property",
        "set-property",
        "read-memory",
        "receive-sb-file",
        "reliable-update",
        "reset",
        "write-memory",
        "generate-key-blob",
        "program-aeskey",
        "update-life-cycle",
        "ele-message",
    ],
)
def test_top_level_command_help(cli_runner: CliRunner, command: str) -> None:
    """Test that each top-level command responds to --help.

    sys.argv is patched because spsdk_mboot_interface inspects sys.argv for '--help'
    to decide whether to skip the hardware interface requirement.
    """
    args = [command, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# get-families (GetFamiliesCommand — hardware required, only --help tested)
# ---------------------------------------------------------------------------


def test_get_families_help(cli_runner: CliRunner) -> None:
    """Test get-families --help."""
    args = ["get-families", "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# key-provisioning group
# ---------------------------------------------------------------------------


def test_key_provisioning_help(cli_runner: CliRunner) -> None:
    """Test key-provisioning group --help."""
    args = ["key-provisioning", "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    [
        "enroll",
        "set_user_key",
        "set_key",
        "write_key_nonvolatile",
        "read_key_nonvolatile",
        "write_key_store",
        "read_key_store",
    ],
)
def test_key_provisioning_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test that each key-provisioning subcommand responds to --help."""
    args = ["key-provisioning", subcommand, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# trust-provisioning group
# ---------------------------------------------------------------------------


def test_trust_provisioning_help(cli_runner: CliRunner) -> None:
    """Test trust-provisioning group --help."""
    args = ["trust-provisioning", "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "subcommand",
    [
        "hsm_store_key",
        "hsm_gen_key",
        "hsm_enc_blk",
        "hsm_enc_sign",
        "oem_gen_master_share",
        "oem_set_master_share",
        "oem_get_cust_cert_dice_puk",
        "wpc_get_id",
        "nxp_get_id",
        "wpc_insert_cert",
        "wpc_sign_csr",
        "dsc_hsm_create_session",
        "dsc_hsm_enc_blk",
        "dsc_hsm_enc_sign",
        "oem_get_cust_dice_response",
        "prove_genuinity",
        "isp_set_wrap_data",
        "el2go_close_device",
    ],
)
def test_trust_provisioning_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test that each trust-provisioning subcommand responds to --help."""
    args = ["trust-provisioning", subcommand, "--help"]
    with patch.object(sys, "argv", args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


# ---------------------------------------------------------------------------
# Error paths — missing interface (no sys.argv patch — let it fail naturally)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "reset",
        "read-memory",
        "write-memory",
        "flash-erase-all",
        "get-property",
    ],
)
def test_command_missing_interface_fails(cli_runner: CliRunner, command: str) -> None:
    """Test that commands fail without a hardware interface specified."""
    result = cli_runner.invoke(main, [command], expected_code=-1)
    assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Error paths — missing required arguments
# ---------------------------------------------------------------------------


def test_efuse_program_once_missing_args(cli_runner: CliRunner) -> None:
    """Test efuse-program-once fails when no interface or args are given."""
    result = cli_runner.invoke(main, ["efuse-program-once"], expected_code=-1)
    assert result.exit_code != 0


def test_flash_erase_region_missing_args(cli_runner: CliRunner) -> None:
    """Test flash-erase-region fails when no interface or args are given."""
    result = cli_runner.invoke(main, ["flash-erase-region"], expected_code=-1)
    assert result.exit_code != 0


def test_fill_memory_missing_args(cli_runner: CliRunner) -> None:
    """Test fill-memory fails when no interface or args are given."""
    result = cli_runner.invoke(main, ["fill-memory"], expected_code=-1)
    assert result.exit_code != 0
