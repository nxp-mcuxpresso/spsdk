#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK common CLI option decorators."""

import logging
import os
from unittest.mock import patch

import click
import pytest

from spsdk.apps.utils.common_cli_options import (
    spsdk_debug_artifacts_option,
    spsdk_output_option_to_config,
)
from spsdk.exceptions import SPSDKError
from tests.cli_runner import CliRunner


def _build_cmd() -> click.Command:
    """Create a minimal Click command using the debug artifacts option."""

    @click.command(name="dummy")
    @spsdk_debug_artifacts_option()
    def dummy(debug_artifacts: str | None) -> None:
        click.echo(f"value={debug_artifacts}")

    return dummy


def _build_deprecated_arguments_cmd() -> click.Command:
    """Create a minimal Click command with deprecated output arguments."""

    @click.command(name="deprecated-arguments")
    @spsdk_output_option_to_config(key_output="output", key_output_format="output_format")
    @click.option("-oc", "--override-config", multiple=True)
    def deprecated_arguments(override_config: tuple[str, ...]) -> None:
        click.echo(f"overrides={override_config}")

    return deprecated_arguments


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


@pytest.mark.parametrize(
    "arguments,message",
    [
        (["--output", "output.bin"], "The --output option is deprecated."),
        (["--output-format", "hex"], "The --output_format option is deprecated."),
        (["--force"], "The --force option is deprecated."),
    ],
)
def test_deprecated_arguments_warning(
    cli_runner: CliRunner, caplog: pytest.LogCaptureFixture, arguments: list[str], message: str
) -> None:
    """Deprecated arguments emit warnings by default."""
    with caplog.at_level(logging.WARNING):
        cli_runner.invoke(_build_deprecated_arguments_cmd(), arguments)
    assert message in caplog.text


@pytest.mark.parametrize(
    "arguments,message",
    [
        (["--output", "output.bin"], "The --output option is deprecated."),
        (["--output-format", "hex"], "The --output_format option is deprecated."),
        (["--force"], "The --force option is deprecated."),
    ],
)
@patch("spsdk.apps.utils.common_cli_options.SPSDK_DEPRECATED_STRICT", True)
def test_deprecated_arguments_strict(
    cli_runner: CliRunner, arguments: list[str], message: str
) -> None:
    """Deprecated arguments fail when strict deprecation reporting is enabled."""
    result = cli_runner.invoke(_build_deprecated_arguments_cmd(), arguments, expected_code=1)
    assert isinstance(result.exception, SPSDKError)
    assert message in str(result.exception)
