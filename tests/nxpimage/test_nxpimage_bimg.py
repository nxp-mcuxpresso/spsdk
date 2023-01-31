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
from spsdk.utils.misc import use_working_directory


@pytest.mark.parametrize(
    "config_file,family",
    [
        ("config.yaml", "rt5xx"),
        ("config.yaml", "rt6xx"),
        ("config.yaml", "lpc55s3x"),
        ("config.yaml", "rt106x"),
        ("config.yaml", "rt105x"),
        ("config.yaml", "rt117x"),
        ("config.yaml", "rt118x"),
    ],
)
def test_nxpimage_bimg_merge(tmpdir, data_dir, config_file, family):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "bootable_image", family, config_file)
        out_file = os.path.join(tmpdir, f"bimg_{family}_merged.bin")
        cmd = f"bootable-image merge -c {config_file} {out_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "bootable_image", family, "merged_image.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,binary,blocks",
    [
        ("rt5xx", "flexspi_nor", "merged_image.bin", ["fcb", "keyblob", "keystore"]),
        ("rt6xx", "flexspi_nor", "merged_image.bin", ["fcb", "keyblob", "keystore"]),
        ("lpc55s3x", "flexspi_nor", "merged_image.bin", ["fcb"]),
    ],
)
def test_nxpimage_bimg_parse_cli(tmpdir, data_dir, family, mem_type, binary, blocks):
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bootable_image", family)
        cmd = f"bootable-image parse -f {family} -m {mem_type} -b {data_folder}/{binary} {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, f"bootable_image_{family}_{mem_type}.yaml"))
        assert os.path.isfile(os.path.join(tmpdir, "fcb.yaml"))
        assert filecmp.cmp(
            os.path.join(tmpdir, "application.bin"),
            os.path.join(data_folder, "application.bin"),
            shallow=False,
        )
        for block in blocks:
            assert filecmp.cmp(
                os.path.join(tmpdir, f"{block}.bin"),
                os.path.join(data_folder, f"{block}.bin"),
                shallow=False,
            )


@pytest.mark.parametrize(
    "family,mem_type,binary",
    [
        ("rt106x", "flexspi_nor", "merged_image.bin"),
        ("rt105x", "flexspi_nor", "merged_image.bin"),
    ],
)
def test_nxpimage_bimg_parse_rt10xx_cli(tmpdir, data_dir, family, mem_type, binary):
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bootable_image", family)
        cmd = f"bootable-image parse -f {family} -m {mem_type} -b {data_folder}/{binary} {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, f"bootable_image_{family}_{mem_type}.yaml"))
        assert os.path.isfile(os.path.join(tmpdir, "fcb.yaml"))
        assert filecmp.cmp(
            os.path.join(tmpdir, "application.bin"),
            os.path.join(data_folder, "application.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "fcb.bin"), os.path.join(data_folder, f"fcb.bin"), shallow=False
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "bdi.bin"),
            os.path.join(data_folder, f"bdi.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "ivt.bin"),
            os.path.join(data_folder, f"ivt.bin"),
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,binary",
    [
        ("rt117x", "flexspi_nor", "merged_image.bin"),
    ],
)
def test_nxpimage_bimg_parse_rt117x_cli(tmpdir, data_dir, family, mem_type, binary):
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bootable_image", family)
        cmd = f"bootable-image parse -f {family} -m {mem_type} -b {data_folder}/{binary} {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, f"bootable_image_{family}_{mem_type}.yaml"))
        assert os.path.isfile(os.path.join(tmpdir, "fcb.yaml"))
        assert filecmp.cmp(
            os.path.join(tmpdir, "application.bin"),
            os.path.join(data_folder, "application.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "fcb.bin"), os.path.join(data_folder, f"fcb.bin"), shallow=False
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "bdi.bin"),
            os.path.join(data_folder, f"bdi.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "ivt.bin"),
            os.path.join(data_folder, f"ivt.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "xmcd.bin"),
            os.path.join(data_folder, f"xmcd.bin"),
            shallow=False,
        )


def test_nxpimage_bimg_parse_rt118x_cli(tmpdir, data_dir):
    family = "rt118x"
    mem_type = "flexspi_nor"
    binary = "merged_image.bin"
    runner = CliRunner()
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bootable_image", family)
        cmd = f"bootable-image parse -f {family} -m {mem_type} -b {data_folder}/{binary} {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, f"bootable_image_{family}_{mem_type}.yaml"))
        assert os.path.isfile(os.path.join(tmpdir, "fcb.yaml"))
        assert filecmp.cmp(
            os.path.join(tmpdir, "ahab_container.bin"),
            os.path.join(data_folder, "ahab_container.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "fcb.bin"), os.path.join(data_folder, f"fcb.bin"), shallow=False
        )


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("rt5xx", ["flexspi_nor"]),
        ("rt6xx", ["flexspi_nor"]),
        ("lpc55s3x", ["flexspi_nor"]),
        ("rt106x", ["flexspi_nor"]),
        ("rt105x", ["flexspi_nor"]),
        ("rt117x", ["flexspi_nor"]),
        ("rt118x", ["flexspi_nor"]),
    ],
)
def test_nxpimage_bimg_template_cli(tmpdir, family, mem_types):
    runner = CliRunner()
    cmd = f"bootable-image get-templates -f {family} {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"bootimg_{family}_{mem_type}.yml")
        assert os.path.isfile(template_name)
