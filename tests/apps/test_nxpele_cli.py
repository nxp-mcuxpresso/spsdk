#!/usr/bin/env python
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
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from spsdk.apps.nxpele import main, safe_main
from spsdk.ele.ele_comm import EleMessageHandler, EleMessageHandlerMBoot, SPSDKEleMessageError
from spsdk.ele.ele_constants import ResponseIndication, ResponseStatus
from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootCommandError
from spsdk.mboot.mcuboot import McuBoot
from spsdk.utils.family import FamilyRevision
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
        "forward-boot-crypto",
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
        "core-reset-release",
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


def test_nxpele_ele_failure_exits_with_indication() -> None:
    """An ELE message failure must exit with the returned response indication as exit code."""
    indication = ResponseIndication.ELE_BAD_SIGNATURE_FAILURE_IND.tag

    def _raise_ele_error() -> None:
        raise SPSDKEleMessageError(
            "ELE Message failed.",
            status=ResponseStatus.ELE_FAILURE_IND.tag,
            indication=indication,
        )

    with patch("spsdk.apps.nxpele.main", _raise_ele_error), pytest.raises(SystemExit) as exc_info:
        safe_main()

    assert exc_info.value.code == indication


def test_nxpele_ele_failure_unknown_indication_exits_with_one() -> None:
    """An unknown ELE indication (0) must fall back to a generic non-zero exit code."""

    def _raise_ele_error() -> None:
        raise SPSDKEleMessageError(
            "ELE Message failed.",
            status=ResponseStatus.ELE_FAILURE_IND.tag,
            indication=0,
        )

    with patch("spsdk.apps.nxpele.main", _raise_ele_error), pytest.raises(SystemExit) as exc_info:
        safe_main()

    assert exc_info.value.code == 1


def _run_nxpele_with_mboot(args: list, device: MagicMock) -> int | str | None:
    """Run nxpele through safe_main with an mBoot ELE handler over a mocked device.

    :param args: nxpele sub-command arguments.
    :param device: Mocked McuBoot device used by the ELE handler.
    :return: Exit code of the application.
    """
    handler = EleMessageHandlerMBoot(device=device, family=FamilyRevision(ELE_FAMILY))
    with (
        patch.object(sys, "argv", ["nxpele", "-f", ELE_FAMILY, *args]),
        patch.object(EleMessageHandler, "get_message_handler", return_value=handler),
        pytest.raises(SystemExit) as exc_info,
    ):
        safe_main()
    return exc_info.value.code


def test_nxpele_reset_tolerates_missing_response() -> None:
    """Reset exits with zero when the chip resets before answering the ELE message."""
    device = MagicMock(spec=McuBoot)
    device.ele_message.side_effect = McuBootCommandError("EleMessage", StatusCode.NO_RESPONSE.tag)

    assert _run_nxpele_with_mboot(["reset"], device) == 0


@pytest.mark.parametrize(
    "error",
    [
        SPSDKConnectionError("Device is not opened for writing"),
        McuBootCommandError("WriteMemory", StatusCode.NO_RESPONSE.tag),
    ],
)
def test_nxpele_reset_failure_exits_with_error(error: SPSDKError) -> None:
    """Reset must exit with a non-zero code when the request cannot be delivered."""
    device = MagicMock(spec=McuBoot)
    device.write_memory.side_effect = error

    assert _run_nxpele_with_mboot(["reset"], device) == 2


@pytest.mark.parametrize(
    "args",
    [
        ["session-open"],
        ["keystore-open", "-s", "0x1", "-i", "0x1", "-n", "0x1"],
        ["public-key-export", "-k", "0x1", "-i", "0x1"],
    ],
)
def test_nxpele_invalid_result_exits_with_error(args: list) -> None:
    """Commands that get no valid handle or key data must exit with a non-zero code."""
    with patch.object(EleMessageHandlerMBoot, "send_message"):
        assert _run_nxpele_with_mboot(args, MagicMock(spec=McuBoot)) == 2


def test_nxpele_export_nxp_prod_ka_puk_failure_exits_with_error(tmp_path: Path) -> None:
    """A failing step of the NXP production KA PUK export must exit with a non-zero code."""
    output = tmp_path / "puk.bin"
    with patch.object(
        EleMessageHandlerMBoot, "send_message", side_effect=SPSDKError("ELE failure")
    ):
        exit_code = _run_nxpele_with_mboot(
            ["export-nxp-prod-ka-puk", "-o", str(output)], MagicMock(spec=McuBoot)
        )
    assert exit_code == 2
    assert not output.exists()
