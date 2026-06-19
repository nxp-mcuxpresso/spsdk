#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for nxpfuses CLI to improve coverage."""

from pathlib import Path

import pytest

from spsdk.apps.nxpfuses import main, prompt_for_write_permission
from tests.cli_runner import CliRunner


def test_nxpfuses_help(cli_runner: CliRunner) -> None:
    """Test nxpfuses --help."""
    result = cli_runner.invoke(main, ["--help"])
    assert "nxpfuses" in result.output.lower() or result.exit_code == 0


def test_nxpfuses_get_families(cli_runner: CliRunner) -> None:
    """Test get-families command."""
    result = cli_runner.invoke(main, ["get-families"])
    assert result.exit_code == 0


def test_nxpfuses_get_template_help(cli_runner: CliRunner) -> None:
    """Test get-template --help."""
    result = cli_runner.invoke(main, ["get-template", "--help"])
    assert result.exit_code == 0


def test_nxpfuses_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test get-template generates a file."""
    outfile = str(tmp_path / "fuses_template.yaml")
    result = cli_runner.invoke(main, ["get-template", "-f", "mimxrt1189", "-o", outfile])
    assert result.exit_code == 0
    import os

    assert os.path.isfile(outfile)


def test_nxpfuses_write_help(cli_runner: CliRunner) -> None:
    """Test write --help."""
    result = cli_runner.invoke(main, ["write", "--help"])
    assert result.exit_code == 0


def test_nxpfuses_write_single_help(cli_runner: CliRunner) -> None:
    """Test write-single --help."""
    result = cli_runner.invoke(main, ["write-single", "--help"])
    assert result.exit_code == 0


def test_nxpfuses_print_help(cli_runner: CliRunner) -> None:
    """Test print --help."""
    result = cli_runner.invoke(main, ["print", "--help"])
    assert result.exit_code == 0


def test_nxpfuses_fuses_script_help(cli_runner: CliRunner) -> None:
    """Test fuses-script --help."""
    result = cli_runner.invoke(main, ["fuses-script", "--help"])
    assert result.exit_code == 0


def test_nxpfuses_get_config_help(cli_runner: CliRunner) -> None:
    """Test get-config --help."""
    result = cli_runner.invoke(main, ["get-config", "--help"])
    assert result.exit_code == 0


def test_prompt_for_write_permission_skip_true() -> None:
    """Test prompt_for_write_permission with skip=True returns True (line 58-59)."""
    result = prompt_for_write_permission(skip=True)
    assert result is True


def test_prompt_for_write_permission_skip_false_yes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test prompt_for_write_permission with skip=False and 'y' input (lines 60-66)."""
    monkeypatch.setattr("click.prompt", lambda *args, **kwargs: "y")
    result = prompt_for_write_permission(skip=False)
    assert result is True


def test_prompt_for_write_permission_skip_false_yes_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test prompt_for_write_permission with skip=False and 'yes' input."""
    monkeypatch.setattr("click.prompt", lambda *args, **kwargs: "yes")
    result = prompt_for_write_permission(skip=False)
    assert result is True


def test_prompt_for_write_permission_skip_false_no(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test prompt_for_write_permission with skip=False and 'n' input (lines 64-66)."""
    monkeypatch.setattr("click.prompt", lambda *args, **kwargs: "n")
    result = prompt_for_write_permission(skip=False)
    assert result is False


@pytest.mark.parametrize("family", ["mimxrt1189", "mimxrt595s", "mcxn947"])
def test_nxpfuses_get_template_families(cli_runner: CliRunner, tmp_path: Path, family: str) -> None:
    """Test get-template for multiple families."""
    outfile = str(tmp_path / f"fuses_{family}.yaml")
    result = cli_runner.invoke(main, ["get-template", "-f", family, "-o", outfile])
    assert result.exit_code == 0
