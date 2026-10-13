#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for the PFR secure installer CLI command."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import Result

from spsdk.apps import pfr as cli
from spsdk.pfr.secure_installer import SIStatus
from tests.cli_runner import CliRunner


def _make_eraser_mock(
    si_status: SIStatus,
    erase_token_programmed: bool = False,
    *,
    family: str = "mcxl255",
) -> MagicMock:
    """Build a mock SecureInstallerEraser.

    :param si_status: SIStatus value to return from check_si_status.
    :param erase_token_programmed: Whether the erase token is programmed.
    :param family: Family name string returned by get_device_info.
    :return: Configured mock.
    """
    eraser = MagicMock()
    if family.startswith("mcxl"):
        cmpa = 0x7E000
        probe = 0x66000
        device_info = {
            "family": family,
            "cmpa_address": f"0x{cmpa:08x}",
            "delete_installer_magic": "0x4027ff65",
            "delete_installer_offset": "0xE0",
            "erase_token_offset": "0xD0",
            "si_probe_address": f"0x{probe:08x}",
            "target_address": f"0x{cmpa + 0xE0:08x}",
            "cmpa_header_marker": "0x5963",
        }
    else:
        cmpa = 0xFE000 if family == "mcxa366" else 0x7E000
        probe = 0xC0000 if family == "mcxa366" else 0x60000
        device_info = {
            "family": family,
            "cmpa_address": f"0x{cmpa:08x}",
            "delete_installer_magic": "0x4027ff65",
            "delete_installer_offset": "0xE0",
            "erase_token_offset": "0xD0",
            "si_probe_address": f"0x{probe:08x}",
            "target_address": f"0x{cmpa + 0xE0:08x}",
        }
    eraser.get_device_info.return_value = device_info
    eraser.check_si_status.return_value = (si_status, erase_token_programmed)
    return eraser


def _invoke_erase_cmd(
    cli_runner: CliRunner,
    eraser: MagicMock,
    extra_args: list[str] | None = None,
    expected_code: int = 0,
) -> Result:
    """Invoke the erase-secure-installer CLI command with a patched eraser.

    :param cli_runner: CLI test runner.
    :param eraser: Pre-configured eraser mock.
    :param extra_args: Additional CLI arguments.
    :param expected_code: Expected exit code.
    :return: Click result object.
    """
    args = ["erase-secure-installer", "--family", "mcxl255"] + (extra_args or [])
    with (
        patch(
            "spsdk.apps.utils.common_cli_options.load_interface_config",
            return_value=MagicMock(IDENTIFIER="usb", get_scan_args=dict),
        ),
        patch(
            "spsdk.apps.utils.common_cli_options.MbootProtocolBase.get_interface_class"
        ) as get_cls,
        patch("spsdk.apps.pfr.McuBoot") as mock_mboot_class,
        patch("spsdk.apps.pfr.SecureInstallerEraser", return_value=eraser),
    ):
        get_cls.return_value.scan_single.return_value = MagicMock()
        mock_mboot = MagicMock()
        mock_mboot.__enter__.return_value = mock_mboot
        mock_mboot_class.return_value = mock_mboot
        return cli_runner.invoke(cli.main, args, expected_code=expected_code)


def test_erase_secure_installer_help(cli_runner: CliRunner) -> None:
    """Test erase-secure-installer command help output.

    :param cli_runner: Click CLI test runner.
    """
    result = cli_runner.invoke(cli.main, ["erase-secure-installer", "--help"])

    assert "Erase Secure Installer" in result.output
    assert "--no-reset" in result.output
    assert "--family" in result.output


def test_erase_secure_installer_command_calls_eraser(cli_runner: CliRunner) -> None:
    """Test secure installer CLI command wiring with valid SI.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_eraser_mock(SIStatus.PRESENT_VALID)
    result = _invoke_erase_cmd(cli_runner, eraser)

    assert result.exit_code == 0
    eraser.check_si_status.assert_called_once()
    eraser.erase.assert_called_once_with(reset=True)
    assert "Erasing Secure Installer on mcxl255" in result.output
    assert "present and valid" in result.output


def test_erase_secure_installer_command_respects_no_reset(cli_runner: CliRunner) -> None:
    """Test secure installer CLI command passes the no-reset flag.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_eraser_mock(SIStatus.PRESENT_VALID, family="mcxa366")
    args = ["erase-secure-installer", "--family", "mcxa366", "--no-reset"]
    with (
        patch(
            "spsdk.apps.utils.common_cli_options.load_interface_config",
            return_value=MagicMock(IDENTIFIER="usb", get_scan_args=dict),
        ),
        patch(
            "spsdk.apps.utils.common_cli_options.MbootProtocolBase.get_interface_class"
        ) as get_cls,
        patch("spsdk.apps.pfr.McuBoot") as mock_mboot_class,
        patch("spsdk.apps.pfr.SecureInstallerEraser", return_value=eraser),
    ):
        get_cls.return_value.scan_single.return_value = MagicMock()
        mock_mboot = MagicMock()
        mock_mboot.__enter__.return_value = mock_mboot
        mock_mboot_class.return_value = mock_mboot
        result = cli_runner.invoke(cli.main, args)

    assert result.exit_code == 0
    eraser.erase.assert_called_once_with(reset=False)
    assert "Please reset the device manually" in result.output


def test_erase_si_already_erased_skips_erase(cli_runner: CliRunner) -> None:
    """When SI is already erased the command exits cleanly without erasing.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_eraser_mock(SIStatus.ERASED)
    result = _invoke_erase_cmd(cli_runner, eraser)

    assert result.exit_code == 0
    eraser.erase.assert_not_called()
    assert "already erased" in result.output


def test_erase_si_corrupted_token_not_programmed_aborts(cli_runner: CliRunner) -> None:
    """When receive-sb-file is not reported, erasure aborts even with blank erase token.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_eraser_mock(SIStatus.PRESENT_CORRUPTED, erase_token_programmed=False)
    result = _invoke_erase_cmd(cli_runner, eraser, expected_code=1)

    assert result.exit_code == 1
    eraser.erase.assert_not_called()
    assert "CORRUPTED" in result.output
    assert "memory-range-invalid status" in result.output


def test_erase_si_corrupted_token_programmed_aborts(cli_runner: CliRunner) -> None:
    """When SI is corrupted and erase token is programmed, command aborts to prevent brick.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_eraser_mock(SIStatus.PRESENT_CORRUPTED, erase_token_programmed=True)
    result = _invoke_erase_cmd(cli_runner, eraser, expected_code=1)

    assert result.exit_code == 1
    eraser.erase.assert_not_called()
    assert "WARNING" in result.output
    assert "already programmed" in result.output
    assert "brick" in result.output.lower() or "cumulative" in result.output.lower()


def test_erase_si_unknown_status_aborts(cli_runner: CliRunner) -> None:
    """When SI presence cannot be confirmed, erasure aborts.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_eraser_mock(SIStatus.UNKNOWN)
    result = _invoke_erase_cmd(cli_runner, eraser, expected_code=1)

    assert result.exit_code == 1
    eraser.erase.assert_not_called()
    assert "unknown" in result.output.lower()
    assert "does not appear to be present" in result.output.lower() or (
        "could not be confirmed" in result.output.lower()
    )


def _make_read_token_eraser(programmed: bool) -> MagicMock:
    """Build a mock SecureInstallerEraser for the read-token command.

    :param programmed: Whether the device holds a non-blank (device-unique) token.
    :return: Configured mock.
    """
    eraser = MagicMock()
    eraser.cmpa_address = 0x7E000
    eraser.erase_token_offset = 0xD0
    if programmed:
        token = (
            (0xDEADBEEF).to_bytes(4, "little")
            + (0xCAFEBABE).to_bytes(4, "little")
            + (0x8BADF00D).to_bytes(4, "little")
            + (0xFEEDFACE).to_bytes(4, "little")
        )
        eraser.read_erase_token.return_value = (token, True)
        eraser.erase_token_as_registers.return_value = {
            "SI_ERASE_TOKEN0": 0xDEADBEEF,
            "SI_ERASE_TOKEN1": 0xCAFEBABE,
            "SI_ERASE_TOKEN2": 0x8BADF00D,
            "SI_ERASE_TOKEN3": 0xFEEDFACE,
        }
    else:
        eraser.read_erase_token.return_value = (b"\xff" * 16, False)
    return eraser


def _invoke_read_token_cmd(
    cli_runner: CliRunner,
    eraser: MagicMock,
    extra_args: list[str] | None = None,
    expected_code: int = 0,
) -> Result:
    """Invoke the read-secure-installer-token CLI command with a patched eraser.

    :param cli_runner: CLI test runner.
    :param eraser: Pre-configured eraser mock.
    :param extra_args: Additional CLI arguments.
    :param expected_code: Expected exit code.
    :return: Click result object.
    """
    args = ["read-secure-installer-token", "--family", "mcxl255"] + (extra_args or [])
    with (
        patch(
            "spsdk.apps.utils.common_cli_options.load_interface_config",
            return_value=MagicMock(IDENTIFIER="usb", get_scan_args=dict),
        ),
        patch(
            "spsdk.apps.utils.common_cli_options.MbootProtocolBase.get_interface_class"
        ) as get_cls,
        patch("spsdk.apps.pfr.McuBoot") as mock_mboot_class,
        patch("spsdk.apps.pfr.SecureInstallerEraser", return_value=eraser),
    ):
        get_cls.return_value.scan_single.return_value = MagicMock()
        mock_mboot = MagicMock()
        mock_mboot.__enter__.return_value = mock_mboot
        mock_mboot_class.return_value = mock_mboot
        return cli_runner.invoke(cli.main, args, expected_code=expected_code)


def test_read_secure_installer_token_help(cli_runner: CliRunner) -> None:
    """The read-token command exposes family, output and the device-only warning.

    :param cli_runner: Click CLI test runner.
    """
    result = cli_runner.invoke(cli.main, ["read-secure-installer-token", "--help"])

    assert "erase token" in result.output.lower()
    assert "--output" in result.output
    assert "--family" in result.output


def test_read_secure_installer_token_programmed(cli_runner: CliRunner) -> None:
    """A programmed token is displayed as raw bytes and four registers with a warning.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_read_token_eraser(programmed=True)
    result = _invoke_read_token_cmd(cli_runner, eraser)

    assert result.exit_code == 0
    eraser.read_erase_token.assert_called_once()
    assert "SI_ERASE_TOKEN0: 0xdeadbeef" in result.output
    assert "SI_ERASE_TOKEN3: 0xfeedface" in result.output
    assert "ONLY on this device" in result.output


def test_read_secure_installer_token_blank(cli_runner: CliRunner) -> None:
    """A blank token reports that the SI has not been erased.

    :param cli_runner: Click CLI test runner.
    """
    eraser = _make_read_token_eraser(programmed=False)
    result = _invoke_read_token_cmd(cli_runner, eraser)

    assert result.exit_code == 0
    eraser.read_erase_token.assert_called_once()
    eraser.erase_token_as_registers.assert_not_called()
    assert "blank" in result.output.lower()
    assert "has not been erased" in result.output.lower()


def test_read_secure_installer_token_writes_config_snippet(
    cli_runner: CliRunner, tmp_path: Path
) -> None:
    """With --output a ready-to-merge CMPA config snippet is written.

    :param cli_runner: Click CLI test runner.
    :param tmp_path: Pytest temporary directory.
    """
    out_file = tmp_path / "si_erase_token.yaml"
    eraser = _make_read_token_eraser(programmed=True)
    result = _invoke_read_token_cmd(cli_runner, eraser, extra_args=["--output", str(out_file)])

    assert result.exit_code == 0
    assert out_file.exists()
    content = out_file.read_text()
    assert "type: CMPA" in content
    assert "SI_ERASE_TOKEN0: '0xdeadbeef'" in content
    assert "SI_ERASE_TOKEN3: '0xfeedface'" in content
    assert "valid ONLY on this device" in content
