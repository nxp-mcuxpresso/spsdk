#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
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
    "family,mem_type,binary",
    [
        ("rt5xx", "flexspi_nor", "merged_image.bin"),
        ("rt6xx", "flexspi_nor", "merged_image.bin"),
    ],
)
def test_nxpimage_bimg_parse_cli(tmpdir, data_dir, family, mem_type, binary):
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
            os.path.join(data_folder, "app.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "fcb.bin"), os.path.join(data_folder, f"fcb.bin"), shallow=False
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "keyblob.bin"),
            os.path.join(data_folder, f"keyblob.bin"),
            shallow=False,
        )
        assert filecmp.cmp(
            os.path.join(tmpdir, "keystore.bin"),
            os.path.join(data_folder, f"keystore.bin"),
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("rt5xx", ["flexspi_nor"]),
        ("rt6xx", ["flexspi_nor"]),
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
