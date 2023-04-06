#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test FCB part of nxpimage app."""
import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import use_working_directory


@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", "flexspi_nor"),
        ("rt6xx", "flexspi_nor"),
        ("rt105x", "flexspi_nor"),
        ("rt106x", "flexspi_nor"),
        ("rt117x", "flexspi_nor"),
        ("lpc55s3x", "flexspi_nor"),
    ],
)
def test_nxpimage_fcb_export(tmpdir, data_dir, family, mem_type):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "fcb", family, f"fcb_{family}_{mem_type}.yaml")
        out_file = os.path.join(tmpdir, f"fcb_{family}_exported.bin")
        cmd = f"bootable-image fcb export -c {config_file} {out_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "fcb", family, "fcb.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,binary",
    [
        ("rt5xx", "flexspi_nor", "fcb.bin"),
        ("rt6xx", "flexspi_nor", "fcb.bin"),
        ("rt105x", "flexspi_nor", "fcb.bin"),
        ("rt106x", "flexspi_nor", "fcb.bin"),
        ("rt117x", "flexspi_nor", "fcb.bin"),
        ("lpc55s3x", "flexspi_nor", "fcb.bin"),
    ],
)
def test_nxpimage_fcb_parse_cli(tmpdir, data_dir, family, mem_type, binary):
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "fcb", family)
        cmd = f"bootable-image fcb parse -f {family} -m {mem_type} -b {data_folder}/{binary} {tmpdir}/fcb_{family}_{mem_type}.yaml"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml"))


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("rt5xx", ["flexspi_nor"]),
        ("rt6xx", ["flexspi_nor"]),
        ("rt105x", ["flexspi_nor"]),
        ("rt106x", ["flexspi_nor"]),
        ("rt117x", ["flexspi_nor"]),
        ("lpc55s3x", ["flexspi_nor"]),
    ],
)
def test_nxpimage_fcb_template_cli(tmpdir, family, mem_types):
    runner = CliRunner()
    cmd = f"bootable-image fcb get-templates -f {family} {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)
