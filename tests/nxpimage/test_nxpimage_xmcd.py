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
from spsdk.image.xmcd.xmcd import XMCD
from spsdk.utils.misc import use_working_directory


@pytest.mark.parametrize(
    "family,mem_type,config_type",
    [
        ("rt117x", "semc_sdram", "simplified"),
        ("rt117x", "semc_sdram", "full"),
        ("rt117x", "flexspi_ram", "simplified"),
        ("rt116x", "semc_sdram", "simplified"),
        ("rt116x", "semc_sdram", "full"),
        ("rt116x", "flexspi_ram", "simplified"),
    ],
)
def test_nxpimage_xmcd_export(tmpdir, data_dir, family, mem_type, config_type):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "xmcd", family, f"{mem_type}_{config_type}.yaml")
        out_file = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}_exported.bin")
        cmd = f"bootable-image xmcd export -c {config_file} {out_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "xmcd", family, f"{mem_type}_{config_type}.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,config_type",
    [
        ("rt117x", "semc_sdram", "simplified"),
        ("rt117x", "semc_sdram", "full"),
        ("rt117x", "flexspi_ram", "simplified"),
        ("rt116x", "semc_sdram", "simplified"),
        ("rt116x", "semc_sdram", "full"),
        ("rt116x", "flexspi_ram", "simplified"),
    ],
)
def test_nxpimage_xmcd_parse_cli(tmpdir, data_dir, family, mem_type, config_type):
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "xmcd", family)
        output_file = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}.yaml")
        cmd = f"bootable-image xmcd parse -f {family} -b {data_folder}/{mem_type}_{config_type}.bin {output_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(output_file)


@pytest.mark.parametrize(
    "family",
    ["rt117x", "rt116x"],
)
def test_nxpimage_xmcd_template_cli(tmpdir, family):
    runner = CliRunner()
    cmd = f"bootable-image xmcd get-templates -f {family} {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0

    mem_types = XMCD.get_supported_memory_types(family)
    for mem_type in mem_types:
        config_types = XMCD.get_supported_configuration_types(family, mem_type)
        for config_type in config_types:
            template_name = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}.yml")
            assert os.path.isfile(template_name)
