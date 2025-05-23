#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test BCA part of nxpimage app."""

import filecmp
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.image.bca.bca import BCA
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family",
    BCA.get_supported_families(),
)
def test_nxpimage_bca_template_cli(cli_runner: CliRunner, tmpdir, family: FamilyRevision):
    cmd = f"bca get-template -f {family.name} --output {tmpdir}/bca_{family.name}.yml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/bca_{family.name}.yml")


@pytest.mark.parametrize(
    "family",
    ["mcxc041", "mcxc141", "mc56f81768", "mc56f81868"],
)
def test_nxpimage_bca_export_cli(cli_runner: CliRunner, tmpdir, data_dir, family: str):
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "bca", family, f"bca_{family}.yaml")
        out_file = os.path.join(tmpdir, f"bca_{family}_exported.bin")
        cmd = ["bca", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "bca", family, f"bca.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family, binary",
    [
        ("mcxc041", "bca.bin"),
        ("mcxc141", "bca.bin"),
        ("mc56f81768", "bca.bin"),
        ("mc56f81868", "bca.bin"),
    ],
)
def test_nxpimage_bca_parse_cli(cli_runner: CliRunner, tmpdir, data_dir, family, binary):
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bca", family)
        binary_path = os.path.join(data_folder, binary)
        out_config = os.path.join(tmpdir, f"bca_{family}.yaml")
        cmd = [
            "bca",
            "parse",
            "-f",
            family,
            "-b",
            binary_path,
            "-o",
            out_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        assert os.path.isfile(out_config)
