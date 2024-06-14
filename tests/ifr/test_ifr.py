#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `ifr` application."""

import filecmp
import os

import pytest

from spsdk.apps import ifr
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family, sector",
    [
        ("kw45xx", "ROMCFG"),
        ("kw45xx", "CMACTable"),
        ("k32w1xx", "ROMCFG"),
        ("k32w1xx", "CMACTable"),
    ],
)
def test_ifr_user_config(cli_runner: CliRunner, tmpdir, family, sector):
    """Test IF CLI - Generation IF user config."""
    cmd = ["get-template", "-f", family, "--sector", sector, "--output", f"{tmpdir}/ifr.yml"]
    cli_runner.invoke(ifr.main, cmd)
    assert os.path.isfile(f"{tmpdir}/ifr.yml")


def test_roundtrip_romcfg(cli_runner: CliRunner, data_dir, tmpdir):
    parse_cmd = [
        "parse-binary",
        "-f",
        "kw45xx",
        "--binary",
        f"{data_dir}/ref.bin",
        "--output",
        f"{tmpdir}/ref.yaml",
    ]
    cli_runner.invoke(ifr.main, parse_cmd)

    generate_cmd = f"generate-binary -f kw45xx --config {tmpdir}/ref.yaml --output {tmpdir}/new.bin"
    cli_runner.invoke(ifr.main, generate_cmd.split())

    assert filecmp.cmp(f"{data_dir}/ref.bin", f"{tmpdir}/new.bin")


def test_roundtrip_cmac_table(cli_runner: CliRunner, data_dir, tmpdir):
    parse_cmd = [
        "parse-binary",
        "-f",
        "kw45xx",
        "--sector",
        "CMACTable",
        "--binary",
        f"{data_dir}/kw45cmac.bin",
        "--output",
        f"{tmpdir}/ref.yaml",
    ]
    cli_runner.invoke(ifr.main, parse_cmd)

    generate_cmd = f"generate-binary -f kw45xx --config {tmpdir}/ref.yaml --output {tmpdir}/new.bin"
    cli_runner.invoke(ifr.main, generate_cmd.split())

    assert filecmp.cmp(f"{data_dir}/kw45cmac.bin", f"{tmpdir}/new.bin")
