#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK common CLI option decorators."""

import os

import click

from spsdk.apps.utils.common_cli_options import spsdk_debug_artifacts_option
from tests.cli_runner import CliRunner


def _build_cmd() -> click.Command:
    """Create a minimal Click command using the debug artifacts option."""

    @click.command(name="dummy")
    @spsdk_debug_artifacts_option()
    def dummy(debug_artifacts: str | None) -> None:
        click.echo(f"value={debug_artifacts}")

    return dummy


def test_debug_artifacts_option_default(cli_runner: CliRunner) -> None:
    """When the option is not used, the value is None and no directory is created."""
    result = cli_runner.invoke(_build_cmd(), [])
    assert "value=None" in result.output


def test_debug_artifacts_option_creates_directory(cli_runner: CliRunner, tmp_path: str) -> None:
    """When a path is provided, the directory is created and the value forwarded."""
    target = os.path.join(str(tmp_path), "artifacts_dir")
    assert not os.path.exists(target)
    result = cli_runner.invoke(_build_cmd(), ["--debug-artifacts", target])
    assert os.path.isdir(target)
    assert f"value={os.path.realpath(target)}" in result.output


def test_debug_artifacts_option_short_name(cli_runner: CliRunner, tmp_path: str) -> None:
    """The short -da alias works and creates the directory."""
    target = os.path.join(str(tmp_path), "artifacts_short")
    result = cli_runner.invoke(_build_cmd(), ["-da", target])
    assert os.path.isdir(target)
    assert f"value={os.path.realpath(target)}" in result.output
