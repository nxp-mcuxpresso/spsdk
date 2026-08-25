#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk_apps.py."""

from unittest.mock import patch

import pytest

from spsdk.apps.spsdk_apps import (
    _detect_shell,
    _get_spsdk_tools,
    _list_available_tools,
    _validate_and_get_tools,
    main,
)
from tests.cli_runner import CliRunner


def test_main_help(cli_runner: CliRunner) -> None:
    """Test main --help."""
    result = cli_runner.invoke(main, ["--help"])
    assert "SPSDK" in result.output


def test_main_version(cli_runner: CliRunner) -> None:
    """Test main --version."""
    result = cli_runner.invoke(main, ["--version"])
    assert result.exit_code == 0


def test_utils_clear_cache(cli_runner: CliRunner) -> None:
    """Test utils clear-cache command (lines 88-90)."""
    with patch("spsdk.apps.spsdk_apps.DatabaseManager"):
        result = cli_runner.invoke(main, ["utils", "clear-cache"])
        assert "cleared" in result.output.lower()


def test_utils_family_info(cli_runner: CliRunner) -> None:
    """Test utils family-info command (lines 355-372)."""
    result = cli_runner.invoke(main, ["utils", "family-info", "-f", "lpc55s69"])
    assert "lpc55s69" in result.output.lower() or result.exit_code == 0


def test_utils_families(cli_runner: CliRunner) -> None:
    """Test utils families command (lines 388-396)."""
    result = cli_runner.invoke(main, ["utils", "families", "-f", "dat"])
    assert result.exit_code == 0
    assert "dat" in result.output.lower()


def test_utils_get_families(cli_runner: CliRunner) -> None:
    """Test utils get-families command."""
    result = cli_runner.invoke(main, ["utils", "get-families", "--help"])
    assert result.exit_code == 0


def test_utils_setup_autocomplete_list_tools(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete --list-tools (lines 313-315)."""
    result = cli_runner.invoke(main, ["utils", "setup-autocomplete", "--list-tools"])
    assert result.exit_code == 0
    assert "nxpimage" in result.output
    assert "nxpshe" in result.output
    assert "spsdk" in result.output


def test_utils_setup_autocomplete_unsupported_shell(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete with unsupported shell gives an error."""
    result = cli_runner.invoke(
        main, ["utils", "setup-autocomplete", "--shell", "fish"], expected_code=2
    )
    assert "fish" in result.output.lower() or "invalid" in result.output.lower()


def test_get_spsdk_tools() -> None:
    """Test _get_spsdk_tools returns list with expected tools."""
    tools = _get_spsdk_tools()
    assert isinstance(tools, list)
    assert "nxpimage" in tools
    assert "blhost" in tools
    assert "pfr" in tools
    assert "nxpshe" in tools
    assert "spsdk" in tools
    assert len(tools) >= 10


def test_list_available_tools(capsys: pytest.CaptureFixture) -> None:
    """Test _list_available_tools prints tools."""
    _list_available_tools()
    captured = capsys.readouterr()
    assert "nxpimage" in captured.out


def test_validate_and_get_tools_all() -> None:
    """Test _validate_and_get_tools with no tools returns all."""
    result = _validate_and_get_tools(())
    assert result is not None
    assert len(result) > 5


def test_validate_and_get_tools_specific() -> None:
    """Test _validate_and_get_tools with specific valid tool."""
    result = _validate_and_get_tools(("nxpimage",))
    assert result == ["nxpimage"]


def test_validate_and_get_tools_invalid(capsys: pytest.CaptureFixture) -> None:
    """Test _validate_and_get_tools with invalid tool returns None."""
    result = _validate_and_get_tools(("nonexistent_tool",))
    assert result is None


def test_setup_autocomplete_dry_run(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete zsh --dry-run."""
    result = cli_runner.invoke(
        main,
        ["utils", "setup-autocomplete", "--shell", "zsh", "--tools", "nxpdevscan", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "dry-run" in result.output.lower()


def test_setup_autocomplete_invalid_tool(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete with invalid tool exits gracefully."""
    result = cli_runner.invoke(
        main,
        ["utils", "setup-autocomplete", "--tools", "nonexistent_tool_xyz"],
    )
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# _detect_shell
# ---------------------------------------------------------------------------


class TestDetectShell:
    """Tests for the _detect_shell autodetection function."""

    def test_windows_returns_powershell(self) -> None:
        """On Windows platform, powershell is returned regardless of $SHELL."""
        with patch("platform.system", return_value="Windows"):
            assert _detect_shell() == "powershell"

    def test_zsh_from_shell_env(self) -> None:
        """$SHELL containing 'zsh' returns 'zsh' on non-Windows."""
        with patch("platform.system", return_value="Linux"):
            with patch.dict("os.environ", {"SHELL": "/bin/zsh"}):
                assert _detect_shell() == "zsh"

    def test_bash_from_shell_env(self) -> None:
        """$SHELL containing 'bash' returns 'bash' on non-Windows."""
        with patch("platform.system", return_value="Linux"):
            with patch.dict("os.environ", {"SHELL": "/bin/bash"}):
                assert _detect_shell() == "bash"

    def test_fallback_to_bash(self) -> None:
        """Unknown $SHELL value falls back to bash on non-Windows."""
        with patch("platform.system", return_value="Linux"):
            with patch.dict("os.environ", {"SHELL": "/bin/sh"}):
                assert _detect_shell() == "bash"

    def test_autodetect_echo_in_output(self, cli_runner: CliRunner) -> None:
        """setup-autocomplete without --shell prints the auto-detected shell."""
        with patch("spsdk.apps.spsdk_apps._detect_shell", return_value="zsh"):
            result = cli_runner.invoke(
                main,
                ["utils", "setup-autocomplete", "--tools", "nxpdevscan", "--dry-run"],
            )
        assert "zsh" in result.output.lower()
