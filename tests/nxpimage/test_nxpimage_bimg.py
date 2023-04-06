#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Bootable Image part of nxpimage app."""
import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_configuration, use_working_directory


@pytest.mark.parametrize(
    "mem_type,family",
    [
        ("flexspi_nor", "rt5xx"),
        ("flexspi_nor", "rt6xx"),
        ("flexspi_nor", "lpc55s3x"),
        ("flexspi_nor", "rt101x"),
        ("flexspi_nor", "rt102x"),
        ("flexspi_nor", "rt105x"),
        ("flexspi_nor", "rt106x"),
        ("flexspi_nor", "rt116x"),
        ("flexspi_nor", "rt117x"),
        ("flexspi_nor", "rt118x"),
        ("semc_nand", "rt116x"),
        ("semc_nand", "rt117x"),
        ("flexspi_nand", "rt116x"),
        ("flexspi_nand", "rt117x"),
    ],
)
def test_nxpimage_bimg_merge(tmpdir, data_dir, mem_type, family):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "bootable_image", family, mem_type, "config.yaml")
        out_file = os.path.join(tmpdir, f"bimg_{family}_merged.bin")
        cmd = f"bootable-image merge -c {config_file} {out_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "bootable_image", family, mem_type, "merged_image.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,blocks",
    [
        ("rt5xx", "flexspi_nor", ["fcb", "keyblob", "keystore", "application"]),
        ("rt6xx", "flexspi_nor", ["fcb", "keyblob", "keystore", "application"]),
        ("lpc55s3x", "flexspi_nor", ["fcb", "application"]),
        ("rt101x", "flexspi_nor", ["fcb", "keyblob", "hab_container"]),
        ("rt102x", "flexspi_nor", ["fcb", "bee_header_0", "bee_header_1", "hab_container"]),
        ("rt105x", "flexspi_nor", ["fcb", "bee_header_0", "bee_header_1", "hab_container"]),
        ("rt106x", "flexspi_nor", ["fcb", "bee_header_0", "bee_header_1", "hab_container"]),
        ("rt116x", "flexspi_nor", ["keyblob", "fcb", "keystore", "hab_container"]),
        ("rt117x", "flexspi_nor", ["keyblob", "fcb", "keystore", "hab_container"]),
        ("rt118x", "flexspi_nor", ["fcb", "ahab_container"]),
        ("rt116x", "semc_nand", ["hab_container"]),
        ("rt116x", "flexspi_nand", ["hab_container"]),
        ("rt117x", "semc_nand", ["hab_container"]),
        ("rt117x", "flexspi_nand", ["hab_container"]),
    ],
)
def test_nxpimage_bimg_parse_cli(tmpdir, data_dir, family, mem_type, blocks):
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bootable_image", family, mem_type)
        cmd = f"bootable-image parse -f {family} -m {mem_type} -b {data_folder}/merged_image.bin {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, f"bootable_image_{family}_{mem_type}.yaml"))
        for block in blocks:
            assert filecmp.cmp(
                os.path.join(tmpdir, f"{block}.bin"),
                os.path.join(data_folder, f"{block}.bin"),
                shallow=False,
            )
        if "fcb" in blocks:
            assert os.path.isfile(os.path.join(tmpdir, "fcb.yaml"))


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("rt5xx", ["flexspi_nor"]),
        ("rt6xx", ["flexspi_nor"]),
        ("lpc55s3x", ["flexspi_nor"]),
        ("rt101x", ["flexspi_nor"]),
        ("rt102x", ["flexspi_nor"]),
        ("rt105x", ["flexspi_nor"]),
        ("rt106x", ["flexspi_nor"]),
        ("rt116x", ["flexspi_nor", "semc_nand", "flexspi_nand"]),
        ("rt117x", ["flexspi_nor", "semc_nand", "flexspi_nand"]),
        ("rt118x", ["flexspi_nor"]),
    ],
)
def test_nxpimage_bimg_template_cli(tmpdir, data_dir, family, mem_types):
    runner = CliRunner()
    cmd = f"bootable-image get-templates -f {family} {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"bootimg_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)
        generated = load_configuration(template_name)
        reference = load_configuration(
            os.path.join(data_dir, "bootable_image", family, mem_type, "config.yaml")
        )
        assert sorted(generated.keys()) == sorted(reference.keys())
