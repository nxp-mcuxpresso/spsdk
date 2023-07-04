#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `ifr` application."""

import filecmp
import os

from click.testing import CliRunner

from spsdk.apps import ifr


def test_ifr_user_config(tmpdir):
    """Test IF CLI - Generation IF user config."""
    cmd = ["get-template", "-d", "kw45xx", "--output", f"{tmpdir}/ifr.yml"]
    runner = CliRunner()
    result = runner.invoke(ifr.main, cmd)
    assert result.exit_code == 0, result.output
    assert os.path.isfile(f"{tmpdir}/ifr.yml")


def test_roundtrip(data_dir, tmpdir):
    parse_cmd = [
        "parse-binary",
        "-d",
        "kw45xx",
        "--binary",
        f"{data_dir}/ref.bin",
        "--output",
        f"{tmpdir}/ref.yaml",
    ]
    runner = CliRunner()
    result = runner.invoke(ifr.main, parse_cmd)
    assert result.exit_code == 0

    generate_cmd = [
        "generate-binary",
        "-d",
        "kw45xx",
        "--user-config",
        f"{tmpdir}/ref.yaml",
        "--output",
        f"{tmpdir}/new.bin",
    ]
    result = runner.invoke(ifr.main, generate_cmd)
    assert result.exit_code == 0

    assert filecmp.cmp(f"{data_dir}/ref.bin", f"{tmpdir}/new.bin")
