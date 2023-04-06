#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test IEE part of nxpimage app."""
import os
import shutil

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory

INPUT_BINARY = "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_bootable_nopadding.bin"


@pytest.mark.parametrize(
    "case, config, reference, keyblobs",
    [
        (
            "aes_xts512",
            "iee_config.yaml",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_nopadding.bin",
            "iee_keyblobs.bin",
        ),
        (
            "aes_xts256",
            "iee_config.yaml",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_nopadding.bin",
            "iee_keyblobs.bin",
        ),
        (
            "aes_ctr256",
            "iee_config.yaml",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_nopadding.bin",
            "iee_keyblobs.bin",
        ),
        (
            "aes_ctr128",
            "iee_config.yaml",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_nopadding.bin",
            "iee_keyblobs.bin",
        ),
        (
            "aes_xts512_multiple",
            "iee_config.yaml",
            "encrypted_blobs.bin",
            "iee_keyblob.bin",
        ),
        (
            "aes_xts512_rt1180",
            "iee_config.yaml",
            "encrypted_blob.bin",
            None,
        ),
    ],
)
def test_nxpimage_iee(tmpdir, data_dir, case, config, reference, keyblobs):
    runner = CliRunner()
    work_dir = os.path.join(tmpdir, "iee", case)
    shutil.copytree(os.path.join(data_dir, "iee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "iee", INPUT_BINARY), work_dir)

    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        output_name = config_dict["output_name"]
        keyblob_name = config_dict["keyblob_name"]
        encrypted_name = config_dict["encrypted_name"]
        cmd = f"iee export {config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(out_dir, output_name))
        assert os.path.isfile(os.path.join(out_dir, encrypted_name))

        if reference:
            encrypted_image_enc = load_binary(reference)
            encrypted_nxpimage = load_binary(os.path.join(out_dir, encrypted_name))
            assert encrypted_image_enc == encrypted_nxpimage

        if keyblobs:
            assert os.path.isfile(os.path.join(out_dir, keyblob_name))
            reference_keyblob = load_binary(keyblobs)
            keyblobs_nxpimage = load_binary(os.path.join(out_dir, keyblob_name))
            assert reference_keyblob == keyblobs_nxpimage


def test_nxpimage_iee_template_cli(tmpdir):
    runner = CliRunner()
    template = os.path.join(tmpdir, "iee_template.yaml")
    cmd = f"iee get-template {template}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(template)
