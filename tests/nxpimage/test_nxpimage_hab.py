#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test BEE part of nxpimage app."""
import filecmp
import os
from shutil import copytree

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_file, use_working_directory


@pytest.fixture()
def hab_data_dir(data_dir):
    return os.path.join(data_dir, "hab")


@pytest.mark.parametrize(
    "configuration, app_name",
    [
        ("rt1160_xip_mdk_unsigned", "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.srec"),
        ("rt1170_QSPI_flash_unsigned", "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.s19"),
        (
            "rt1170_RAM_non_xip_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.s19",
        ),
        ("rt1170_RAM_unsigned", "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.s19"),
        ("rt1170_flashloader_unsigned", "evkmimxrt1170_flashloader.srec"),
        ("rt1170_flashloader_authenticated", "flashloader.srec"),
        ("rt1170_RAM_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19"),
        ("rt1050_xip_image_iar_authenticated", "led_blinky_xip_srec_iar.srec"),
        ("rt1170_semcnand_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19"),
        ("rt1165_semcnand_authenticated", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        ("rt1165_flashloader_authenticated", "flashloader.srec"),
        ("rt1165_semcnand_encrypted", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        ("rt1160_RAM_encrypted", "validationboard_imxrt1160_iled_blinky_cm7_int_RAM.s19"),
    ],
)
def test_nxpimage_hab_export(tmpdir, hab_data_dir, configuration, app_name):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    command_file_path = os.path.join(config_dir, "config.bd")
    ref_file_path = os.path.join(config_dir, "output.bin")
    app_file_path = os.path.join(config_dir, app_name)
    runner = CliRunner()
    with use_working_directory(tmpdir):
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        cmd = [
            "hab",
            "export",
            "--command",
            command_file_path,
            "--output",
            output_file_path,
            app_file_path,
        ]
        result = runner.invoke(nxpimage.main, cmd)
        assert result.exit_code == 0
        assert os.path.isfile(output_file_path)
        assert load_file(ref_file_path, mode="rb") == load_file(output_file_path, mode="rb")


@pytest.mark.parametrize(
    "configuration, source_bin, segments",
    [
        (
            "rt1170_RAM_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.bin",
            ["ivt", "bdt", "app"],
        ),
    ],
)
def test_nxpimage_hab_parse(tmpdir, hab_data_dir, configuration, source_bin, segments):
    config_dir = os.path.join(hab_data_dir, "parse", configuration)
    source_bin_path = os.path.join(config_dir, source_bin)
    runner = CliRunner()
    with use_working_directory(tmpdir):
        cmd = ["hab", "parse", "--binary", source_bin_path, str(tmpdir)]
        result = runner.invoke(nxpimage.main, cmd)
        assert result.exit_code == 0
        for segment in segments:
            segment_file_name = f"{segment}.bin"
            segment_file_path = os.path.join(tmpdir, segment_file_name)
            assert os.path.isfile(segment_file_path)
            assert filecmp.cmp(
                os.path.join(config_dir, segment_file_name),
                segment_file_path,
                shallow=False,
            )


def test_nxpimage_hab_export_secret_key_generated(tmpdir, hab_data_dir):
    config_dir = os.path.join(hab_data_dir, "export", "rt1165_semcnand_encrypted_random")
    runner = CliRunner()
    with use_working_directory(tmpdir):
        copytree(config_dir, tmpdir, dirs_exist_ok=True)
        command_file_path = os.path.join(tmpdir, "config.bd")
        app_file_path = os.path.join(tmpdir, "evkmimxrt1064_iled_blinky_SDRAM.s19")
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        cmd = (
            f"hab export --command {command_file_path} --output {output_file_path} {app_file_path}"
        )
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(output_file_path)
        secret_key_path = os.path.join(
            tmpdir, "gen_hab_encrypt", "evkmimxrt1064_iled_blinky_SDRAM_hab_dek.bin"
        )
        assert os.path.isfile(secret_key_path)
        secret_key = load_file(secret_key_path, "rb")
        assert len(secret_key) == 32
