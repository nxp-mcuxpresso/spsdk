#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for nxpimage_hse CLI commands to improve coverage."""

from pathlib import Path

import pytest

from spsdk.apps.nxpimage_apps.nxpimage_hse import hse_group
from spsdk.image.hse.key_catalog import KeyCatalogCfg
from spsdk.image.hse.key_info import KeyInfo
from tests.cli_runner import CliRunner


def test_hse_help(cli_runner: CliRunner) -> None:
    """Test hse --help."""
    result = cli_runner.invoke(hse_group, ["--help"])
    assert result.exit_code == 0


@pytest.mark.parametrize("group", ["key-info", "key-catalog", "smr-entry", "cr-entry"])
def test_hse_subgroup_help(cli_runner: CliRunner, group: str) -> None:
    """Test each hse subgroup --help."""
    result = cli_runner.invoke(hse_group, [group, "--help"])
    assert result.exit_code == 0


@pytest.mark.parametrize("group", ["key-info", "key-catalog", "smr-entry", "cr-entry"])
def test_hse_subgroup_get_families(cli_runner: CliRunner, group: str) -> None:
    """Test get-families for each hse subgroup."""
    result = cli_runner.invoke(hse_group, [group, "get-families"])
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "group,cmd",
    [
        ("key-info", "get-template"),
        ("key-info", "export"),
        ("key-info", "parse"),
        ("key-catalog", "get-template"),
        ("key-catalog", "export"),
        ("key-catalog", "parse"),
        ("smr-entry", "get-template"),
        ("smr-entry", "export"),
        ("smr-entry", "parse"),
        ("smr-entry", "create-auth-tag"),
        ("cr-entry", "get-template"),
        ("cr-entry", "export"),
        ("cr-entry", "parse"),
    ],
)
def test_hse_subcommand_help(cli_runner: CliRunner, group: str, cmd: str) -> None:
    """Test --help for all hse subcommands."""
    result = cli_runner.invoke(hse_group, [group, cmd, "--help"])
    assert result.exit_code == 0


def test_key_info_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test key-info get-template generates a file."""
    family = KeyInfo.get_supported_families()[0].name
    outfile = str(tmp_path / "key_info.yaml")
    result = cli_runner.invoke(hse_group, ["key-info", "get-template", "-f", family, "-o", outfile])
    assert result.exit_code == 0
    import os

    assert os.path.isfile(outfile)


def test_key_catalog_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test key-catalog get-template generates a file."""
    family = KeyCatalogCfg.get_supported_families()[0].name
    outfile = str(tmp_path / "key_catalog.yaml")
    result = cli_runner.invoke(
        hse_group, ["key-catalog", "get-template", "-f", family, "-o", outfile]
    )
    assert result.exit_code == 0
    import os

    assert os.path.isfile(outfile)


@pytest.mark.parametrize("family", ["mcxe315", "mcxe317"])
def test_key_info_get_template_families(cli_runner: CliRunner, tmp_path: Path, family: str) -> None:
    """Test key-info get-template for multiple families."""
    outfile = str(tmp_path / f"key_info_{family}.yaml")
    result = cli_runner.invoke(hse_group, ["key-info", "get-template", "-f", family, "-o", outfile])
    assert result.exit_code == 0


def test_smr_entry_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test smr-entry get-template."""
    from spsdk.image.hse.smr import SmrEntry

    families = SmrEntry.get_supported_families()
    if not families:
        pytest.skip("No families support smr-entry")
    family = families[0].name
    outfile = str(tmp_path / "smr_entry.yaml")
    result = cli_runner.invoke(
        hse_group, ["smr-entry", "get-template", "-f", family, "-o", outfile]
    )
    assert result.exit_code == 0
    import os

    assert os.path.isfile(outfile)


def test_cr_entry_get_template(cli_runner: CliRunner, tmp_path: Path) -> None:
    """Test cr-entry get-template."""
    from spsdk.image.hse.core_reset import CoreResetEntry as CrEntry

    families = CrEntry.get_supported_families()
    if not families:
        pytest.skip("No families support cr-entry")
    family = families[0].name
    outfile = str(tmp_path / "cr_entry.yaml")
    result = cli_runner.invoke(hse_group, ["cr-entry", "get-template", "-f", family, "-o", outfile])
    assert result.exit_code == 0
    import os

    assert os.path.isfile(outfile)
