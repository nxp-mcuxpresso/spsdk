#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test BEE part of nxpimage app."""
import os
import shutil

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKOverlapError
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory

INPUT_BINARY = "evkbimxrt1050_iled_blinky_ext_FLASH_unencrypted_nopadding.bin"


@pytest.mark.parametrize(
    "case, config, reference, engines",
    [
        (
            "both_engines_ctr",
            "bee_config.yaml",
            "evkbimxrt1050_iled_blinky_ext_FLASH_bootable_nopadding.bin",
            [0, 1],
        ),
        ("both_engines_generated_header", "bee_config.yaml", None, [0, 1]),
        ("one_engine_generated_header", "bee_config.yaml", None, [0]),
    ],
)
def test_nxpimage_bee(tmpdir, data_dir, case, config, reference, engines):
    runner = CliRunner()
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"bee export {config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(out_dir, "encrypted.bin"))
        for engine in engines:
            assert os.path.isfile(os.path.join(out_dir, f"{engine}_bee_ehdr.bin"))
        if reference:
            encrypted_image_enc = load_binary(reference)
            encrypted_nxpimage = load_binary(os.path.join(out_dir, "encrypted.bin"))
            assert encrypted_image_enc == encrypted_nxpimage


@pytest.mark.parametrize(
    "case, config",
    [
        ("both_engines_generated_header_overlap", "bee_config.yaml"),
    ],
)
def test_nxpimage_bee_overlap(tmpdir, data_dir, case, config):
    runner = CliRunner()
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        cmd = f"bee export {config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code != 0


def test_nxpimage_bee_template_cli(tmpdir):
    runner = CliRunner()
    template = os.path.join(tmpdir, "bee_template.yaml")
    cmd = f"bee get-template {template}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(template)
