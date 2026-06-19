#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Comprehensive pytest tests for nxpele CLI application.

Tests cover all command groups and subcommands using --help invocations and
hardware-free commands (get-families) to maximize code coverage without
requiring a real ELE-enabled device.

Note: nxpele's main group callback uses ``is_click_help(ctx, sys.argv)`` to
decide whether to skip hardware initialization.  When the CliRunner is used
inside pytest, ``sys.argv`` contains the pytest command line, not the
invocation arguments.  We therefore patch ``sys.argv`` for every test that
uses ``--help`` so that the guard correctly bypasses ELE communication setup.
"""

import sys
from unittest.mock import patch

import pytest

from spsdk.apps.nxpele import main
from tests.cli_runner import CliRunner

# Family available in nxpele (see `nxpele --help`)
ELE_FAMILY = "mimxrt1189"


def _invoke_help(cli_runner: CliRunner, args: list) -> None:
    """Helper: invoke with sys.argv patched so is_click_help returns True.

    :param cli_runner: CliRunner instance.
    :param args: CLI arguments (should contain '--help').
    """
    with patch.object(sys, "argv", ["nxpele"] + args):
        result = cli_runner.invoke(main, args)
    assert "Show this message and exit." in result.output


def _invoke_no_hw(cli_runner: CliRunner, args: list) -> None:
    """Helper: invoke hardware-free command (e.g. get-families) with sys.argv patched.

    :param cli_runner: CliRunner instance.
    :param args: CLI arguments (should NOT require hardware).
    """
    with patch.object(sys, "argv", ["nxpele"] + args):
        result = cli_runner.invoke(main, args)
    assert result.output


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------


def test_nxpele_help(cli_runner: CliRunner) -> None:
    """Test nxpele --help."""
    _invoke_help(cli_runner, ["--help"])


def test_nxpele_get_families(cli_runner: CliRunner) -> None:
    """Test nxpele get-families (hardware-free)."""
    _invoke_no_hw(cli_runner, ["-f", ELE_FAMILY, "get-families"])


# ---------------------------------------------------------------------------
# Simple subcommands (no hardware) – test with --help
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "subcommand",
    [
        "ping",
        "enable-apc",
        "enable-rtc",
        "reset-apc-context",
        "reset",
        "get-ele-fw-status",
        "get-ele-trng-state",
        "get-ele-fw-version",
        "get-info",
        "ele-fw-auth",
        "dump-debug-buffer",
        "read-common-fuse",
        "read-shadow-fuse",
        "oem-cntn-auth",
        "commit",
        "derive-key",
        "verify-image",
        "release-container",
        "forward-lifecycle-update",
        "signed-message",
        "get-events",
        "start-trng",
        "load-keyblob",
        "write-fuse",
        "write-shadow-fuse",
        "session-open",
        "sab-init",
        "session-close",
        "keystore-open",
        "keystore-close",
        "public-key-export",
        "export-nxp-prod-ka-puk",
        "batch",
    ],
)
def test_nxpele_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test that every nxpele subcommand shows help text."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, subcommand, "--help"])


# ---------------------------------------------------------------------------
# generate-keyblob group
# ---------------------------------------------------------------------------


def test_generate_keyblob_help(cli_runner: CliRunner) -> None:
    """Test generate-keyblob group --help."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, "generate-keyblob", "--help"])


@pytest.mark.parametrize("subcommand", ["DEK", "OTFAD", "OTFAD-KEYBLOB", "IEE", "IEE-KEYBLOB"])
def test_generate_keyblob_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test generate-keyblob sub-command --help."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, "generate-keyblob", subcommand, "--help"])


# ---------------------------------------------------------------------------
# hse group
# ---------------------------------------------------------------------------


def test_hse_help(cli_runner: CliRunner) -> None:
    """Test hse group --help."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, "hse", "--help"])


@pytest.mark.parametrize(
    "subcommand",
    [
        "get-key-info",
        "fw-update",
        "img-verify",
        "img-sign",
        "get-attr",
        "smr-entry-install",
        "smr-entry-erase",
        "smr-verify",
        "cr-entry-install",
        "cr-entry-erase",
        "key-import",
        "format-key-catalog",
        "fw-integrity-check",
        "fw-erase",
        "activate-passive-block",
    ],
)
def test_hse_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test hse subcommand --help."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, "hse", subcommand, "--help"])


def test_hse_set_attr_help(cli_runner: CliRunner) -> None:
    """Test hse set-attr group --help."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, "hse", "set-attr", "--help"])


@pytest.mark.parametrize(
    "subcommand",
    [
        "enable-publish-keystore-ram-to-flash",
        "secure-lifecycle",
        "debug-auth-mode",
    ],
)
def test_hse_set_attr_subcommand_help(cli_runner: CliRunner, subcommand: str) -> None:
    """Test hse set-attr subcommand --help."""
    _invoke_help(cli_runner, ["-f", ELE_FAMILY, "hse", "set-attr", subcommand, "--help"])


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------


def test_nxpele_missing_family_fails(cli_runner: CliRunner) -> None:
    """Test that omitting --family causes a non-zero exit code."""
    cli_runner.invoke(main, ["get-families"], expected_code=2)


def test_nxpele_invalid_family_fails(cli_runner: CliRunner) -> None:
    """Test that an invalid family value causes a non-zero exit code."""
    cli_runner.invoke(main, ["-f", "not_a_real_family", "get-families"], expected_code=2)
