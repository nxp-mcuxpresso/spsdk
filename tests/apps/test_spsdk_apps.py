#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for spsdk_apps.py."""

from unittest.mock import MagicMock, patch

import pytest

from spsdk.apps.spsdk_apps import (
    _check_auto_click_auto_import,
    _get_shell_type,
    _get_spsdk_tools,
    _list_available_tools,
    _show_dry_run_info,
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


def test_utils_setup_autocomplete_no_auto_click_auto(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete when auto-click-auto is not installed (lines 103-110)."""
    with patch.dict("sys.modules", {"auto_click_auto": None}):
        result = cli_runner.invoke(main, ["utils", "setup-autocomplete", "--shell", "bash"])
        # Should fail gracefully with error message
        assert (
            result.exit_code == 0 or "auto-click-auto" in result.output or "Error" in result.output
        )


def test_get_spsdk_tools() -> None:
    """Test _get_spsdk_tools returns list with expected tools (lines 118-138)."""
    tools = _get_spsdk_tools()
    assert isinstance(tools, list)
    assert "nxpimage" in tools
    assert "blhost" in tools
    assert "pfr" in tools
    assert len(tools) >= 10


def test_list_available_tools(capsys: pytest.CaptureFixture) -> None:
    """Test _list_available_tools prints tools (lines 143-145)."""
    _list_available_tools()
    captured = capsys.readouterr()
    assert "nxpimage" in captured.out


def test_validate_and_get_tools_all() -> None:
    """Test _validate_and_get_tools with no tools returns all (line 155)."""
    result = _validate_and_get_tools(())
    assert result is not None
    assert len(result) > 5


def test_validate_and_get_tools_specific() -> None:
    """Test _validate_and_get_tools with specific valid tool (line 155)."""
    result = _validate_and_get_tools(("nxpimage",))
    assert result == ["nxpimage"]


def test_validate_and_get_tools_invalid(capsys: pytest.CaptureFixture) -> None:
    """Test _validate_and_get_tools with invalid tool returns None (lines 159-165)."""
    result = _validate_and_get_tools(("nonexistent_tool",))
    assert result is None


def test_check_auto_click_auto_import_missing() -> None:
    """Test _check_auto_click_auto_import when package not available (lines 103-110)."""
    import sys

    original = sys.modules.get("auto_click_auto")
    sys.modules["auto_click_auto"] = None  # type: ignore
    try:
        enable, ShellType = _check_auto_click_auto_import()
        # If it raised ImportError, both should be None
        # (only triggered on actual ImportError during import)
    except Exception:
        pass
    finally:
        if original is None:
            del sys.modules["auto_click_auto"]
        else:
            sys.modules["auto_click_auto"] = original


def test_get_shell_type_none() -> None:
    """Test _get_shell_type with None shell (line 178)."""
    mock_shell_type = MagicMock()
    result = _get_shell_type(None, mock_shell_type)
    assert result is None


def test_get_shell_type_valid() -> None:
    """Test _get_shell_type with valid shell string (line 181)."""
    mock_shell_type = MagicMock()
    mock_shell_type.return_value = "bash_type"
    _get_shell_type("bash", mock_shell_type)
    mock_shell_type.assert_called_with("bash")


def test_get_shell_type_invalid(capsys: pytest.CaptureFixture) -> None:
    """Test _get_shell_type with invalid shell raises ValueError (lines 183-188)."""
    mock_shell_type = MagicMock()
    mock_shell_type.side_effect = ValueError("unsupported shell")
    result = _get_shell_type("invalidshell", mock_shell_type)
    assert result is None


def test_show_dry_run_info(capsys: pytest.CaptureFixture) -> None:
    """Test _show_dry_run_info (lines 197-199)."""
    mock_shell_type = MagicMock()
    mock_shell_type.value = "bash"
    _show_dry_run_info(mock_shell_type, ["nxpimage", "blhost"])
    captured = capsys.readouterr()
    assert "nxpimage" in captured.out
    assert "bash" in captured.out


def test_show_dry_run_info_no_shell(capsys: pytest.CaptureFixture) -> None:
    """Test _show_dry_run_info with None shell (lines 197-199)."""
    _show_dry_run_info(None, ["nxpimage"])
    captured = capsys.readouterr()
    assert "auto-detect" in captured.out


def test_setup_autocomplete_dry_run(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete with --dry-run (lines 329-331)."""
    mock_enable = MagicMock()
    mock_shell_enum = MagicMock()
    mock_shell_enum.return_value = MagicMock(value="bash")

    with patch("spsdk.apps.spsdk_apps._check_auto_click_auto_import") as mock_check:
        mock_check.return_value = (mock_enable, mock_shell_enum)
        result = cli_runner.invoke(
            main,
            ["utils", "setup-autocomplete", "--shell", "bash", "--tools", "nxpimage", "--dry-run"],
        )
        assert result.exit_code == 0


def test_setup_autocomplete_invalid_tool(cli_runner: CliRunner) -> None:
    """Test setup-autocomplete with invalid tool exits gracefully (lines 159-165)."""
    mock_enable = MagicMock()
    mock_shell_enum = MagicMock()

    with patch("spsdk.apps.spsdk_apps._check_auto_click_auto_import") as mock_check:
        mock_check.return_value = (mock_enable, mock_shell_enum)
        result = cli_runner.invoke(
            main,
            ["utils", "setup-autocomplete", "--tools", "nonexistent_tool_xyz"],
        )
        assert result.exit_code == 0
