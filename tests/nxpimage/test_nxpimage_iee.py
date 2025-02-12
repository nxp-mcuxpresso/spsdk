#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test IEE part of nxpimage app."""
import os
import shutil

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.utils.crypto.iee import IeeNxp
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner

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
def test_nxpimage_iee(cli_runner: CliRunner, tmpdir, data_dir, case, config, reference, keyblobs):
    work_dir = os.path.join(tmpdir, "iee", case)
    shutil.copytree(os.path.join(data_dir, "iee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "iee", INPUT_BINARY), work_dir)

    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        output_name = config_dict["output_name"]
        keyblob_name = config_dict["keyblob_name"]
        encrypted_name = config_dict["encrypted_name"]
        cmd = f"iee export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
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


@pytest.mark.parametrize(
    "family",
    [
        ("rt116x"),
        ("rt117x"),
        ("mimxrt1189"),
    ],
)
def test_nxpimage_iee_template_cli(cli_runner: CliRunner, tmpdir, family):
    template = os.path.join(tmpdir, "iee_template.yaml")
    cmd = f"iee get-template --family {family} --output {template}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(template)


@pytest.mark.parametrize(
    "case, config",
    [
        (
            "aes_xts512_custom_names",
            "iee_config.yaml",
        )
    ],
)
def test_iee_custom_output(cli_runner: CliRunner, tmpdir, data_dir, case, config):
    work_dir = os.path.join(tmpdir, "iee", case)
    shutil.copytree(os.path.join(data_dir, "iee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "iee", INPUT_BINARY), work_dir)

    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        config_dict["output_name"] = os.path.join(tmpdir, "iee_output")
        config_dict["keyblob_name"] = "keyblob"
        config_dict["encrypted_name"] = ""

        modified_config = os.path.join(work_dir, "modified_config.yaml")
        with open(modified_config, "w") as f:
            yaml.dump(config_dict, f)
        cmd = f"iee export -c {modified_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        assert os.path.isfile(os.path.join(out_dir, "keyblob.bin"))
        assert not os.path.isfile(os.path.join(out_dir, "iee_rt117x_blhost.bcf"))
        assert os.path.isfile(os.path.join(out_dir, "readme.txt"))
        assert os.path.isfile(config_dict["output_name"] + ".bin")


@pytest.mark.parametrize(
    "case,config,blhost_bcf_res",
    [
        (
            "aes_xts512",
            "iee_config.yaml",
            [
                "efuse-program-once 96 0x3020100 --no-verify",
                "efuse-program-once 103 0x1F1E1D1C --no-verify",
                "efuse-program-once 104 0x23222120 --no-verify",
                "efuse-program-once 111 0x3F3E3D3C --no-verify",
                "efuse-program-once 14 0x100 --no-verify",
                "efuse-program-once 23 0x1000 --no-verify",
                "efuse-program-once 9 0xC --no-verify",
                "efuse-program-once 20 0x2 --no-verify",
            ],
        ),
        (
            "aes_xts512_rt1180",
            "iee_config.yaml",
            [],
        ),
    ],
)
def test_nxpimage_iee_export_bcf(data_dir, case, config, blhost_bcf_res):
    config_dir = os.path.join(data_dir, "iee", case)
    config1_dir = os.path.join(data_dir, "iee")
    config_data = load_configuration(os.path.join(config_dir, config))
    iee = IeeNxp.load_from_config(config_data, config_dir, search_paths=[config_dir, config1_dir])
    bcf = iee.get_blhost_script_otp_kek()
    for result in blhost_bcf_res:
        assert result in bcf
