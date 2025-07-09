#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test FCF part of nxpimage app."""

import filecmp
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.image.fcf.fcf import FCF
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family",
    FCF.get_supported_families(),
)
def test_nxpimage_fcf_template_cli(cli_runner: CliRunner, tmpdir, family: FamilyRevision):
    cmd = f"fcf get-template -f {family.name} --output {tmpdir}/fcf_{family.name}.yml"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/fcf_{family.name}.yml")


@pytest.mark.parametrize("family", ["mcxc041", "mcxc141", "mc56f81768", "mc56f81868"])
def test_nxpimage_fcf_export_cli(cli_runner: CliRunner, tmpdir, data_dir, family: str):
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "fcf", family, f"fcf_{family}.yaml")
        out_file = os.path.join(tmpdir, f"fcf_{family}_exported.bin")
        cmd = ["fcf", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "fcf", family, "fcf.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family, binary",
    [
        ("mcxc041", "fcf.bin"),
        ("mcxc141", "fcf.bin"),
        ("mc56f81768", "fcf.bin"),
        ("mc56f81868", "fcf.bin"),
    ],
)
def test_nxpimage_fcf_parse_cli(cli_runner: CliRunner, tmpdir, data_dir, family, binary):
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "fcf", family)
        binary_path = os.path.join(data_folder, binary)
        out_config = os.path.join(tmpdir, f"fcf_{family}.yaml")
        cmd = [
            "fcf",
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
