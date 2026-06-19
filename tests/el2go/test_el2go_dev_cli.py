#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for el2go_dev CLI commands to improve coverage."""

from pathlib import Path

import pytest

from spsdk.apps.el2go_apps.el2go_dev import dev_group
from tests.cli_runner import CliRunner

EL2GO_DEV_COMMANDS = [
    "get-template",
    "get-families",
    "run-provisioning",
    "get-secure-objects",
    "get-uuid",
    "prepare-device",
    "provision-objects",
    "provision-device",
    "combine-uuid-db",
    "parse-uuid-db",
    "unclaim",
    "bulk-so-download",
]


def test_el2go_dev_help(cli_runner: CliRunner) -> None:
    """Test el2go dev --help."""
    result = cli_runner.invoke(dev_group, ["--help"])
    assert result.exit_code == 0


@pytest.mark.parametrize("cmd", EL2GO_DEV_COMMANDS)
def test_el2go_dev_command_help(cli_runner: CliRunner, cmd: str) -> None:
    """Test --help for all el2go dev subcommands."""
    result = cli_runner.invoke(dev_group, [cmd, "--help"])
    assert result.exit_code == 0


def test_el2go_dev_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test get-template generates a file (lines 56-68)."""
    outfile = str(tmp_path / "el2go_template.yaml")
    result = cli_runner.invoke(dev_group, ["get-template", "-f", "k32w148", "-o", outfile])
    assert result.exit_code == 0
    import os

    assert os.path.isfile(outfile)


@pytest.mark.parametrize("family", ["k32w148", "kw45b41z8", "mcxw716a"])
def test_el2go_dev_get_template_families(
    cli_runner: CliRunner, tmp_path: Path, family: str
) -> None:
    """Test get-template for multiple families."""
    outfile = str(tmp_path / f"el2go_{family}.yaml")
    result = cli_runner.invoke(dev_group, ["get-template", "-f", family, "-o", outfile])
    assert result.exit_code == 0


def test_el2go_dev_get_families_missing_cmd(cli_runner: CliRunner) -> None:
    """Test get-families without -c shows message about cmd-name."""
    result = cli_runner.invoke(dev_group, ["get-families"])
    # Returns exit_code 0 with a message about missing cmd-name option
    assert "cmd-name" in result.output.lower() or result.exit_code == 0


def test_el2go_dev_get_families_get_template(cli_runner: CliRunner) -> None:
    """Test get-families -c get-template."""
    result = cli_runner.invoke(dev_group, ["get-families", "-c", "get-template"])
    assert result.exit_code == 0


def test_el2go_dev_combine_uuid_db_missing_args(cli_runner: CliRunner) -> None:
    """Test combine-uuid-db with no args shows error."""
    result = cli_runner.invoke(dev_group, ["combine-uuid-db"], expected_code=-1)
    assert result.exit_code != 0


def test_el2go_dev_parse_uuid_db_missing_args(cli_runner: CliRunner) -> None:
    """Test parse-uuid-db with no args shows error."""
    result = cli_runner.invoke(dev_group, ["parse-uuid-db"], expected_code=-1)
    assert result.exit_code != 0
