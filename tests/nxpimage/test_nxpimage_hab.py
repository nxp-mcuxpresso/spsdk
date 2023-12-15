#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test BEE part of nxpimage app."""
import filecmp
import os
import shutil
from shutil import copytree

import pytest

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner


@pytest.fixture()
def hab_data_dir(data_dir):
    return os.path.join(data_dir, "hab")


def export_hab_cli(cli_runner: CliRunner, output_path: str, config_path: str, app_path: str):
    cmd = [
        "hab",
        "export",
        "--command",
        config_path,
        "--output",
        output_path,
        app_path,
    ]

    cli_runner.invoke(nxpimage.main, cmd)


@pytest.mark.parametrize(
    "configuration, app_name, check_areas",
    [
        ("rt1160_xip_mdk_unsigned", "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.srec", []),
        ("rt1170_QSPI_flash_unsigned", "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.s19", []),
        (
            "rt1170_RAM_non_xip_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.s19",
            [],
        ),
        ("rt1170_RAM_unsigned", "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.s19", []),
        ("rt1170_flashloader_unsigned", "evkmimxrt1170_flashloader.srec", []),
        ("rt1170_flashloader_authenticated", "flashloader.srec", []),
        ("rt1170_RAM_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19", []),
        ("rt1050_xip_image_iar_authenticated", "led_blinky_xip_srec_iar.srec", []),
        ("rt1170_semcnand_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19", []),
        ("rt1165_semcnand_authenticated", "evkmimxrt1064_iled_blinky_SDRAM.s19", []),
        ("rt1165_flashloader_authenticated", "flashloader.srec", []),
        ("rt1165_semcnand_encrypted", "evkmimxrt1064_iled_blinky_SDRAM.s19", []),
        ("rt1160_RAM_encrypted", "validationboard_imxrt1160_iled_blinky_cm7_int_RAM.s19", []),
        (
            "rt1173_flashloader_authenticated_ecc",
            "flashloader.srec",
            [(0, 0x144E8), (0x1466F, 0x148BC), (0x14A43, 0x16000)],
        ),
    ],
)
def test_nxpimage_hab_export(
    cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, app_name, check_areas
):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    with use_working_directory(tmpdir):
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(
            cli_runner,
            output_file_path,
            os.path.join(config_dir, "config.bd"),
            os.path.join(config_dir, app_name),
        )
        assert os.path.isfile(output_file_path)
        ref_binary = load_binary(os.path.join(config_dir, "output.bin"))
        new_binary = load_binary(output_file_path)
        assert len(ref_binary) == len(new_binary)
        # the actual signature check must avoided if ECC keys are used as they change every time
        if check_areas:
            for area in check_areas:
                assert ref_binary[area[0] : area[1]] == new_binary[area[0] : area[1]]
        else:
            assert ref_binary == new_binary


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
def test_nxpimage_hab_convert(cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, app_name):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    shutil.copytree(config_dir, tmpdir, dirs_exist_ok=True)
    command_file_path = os.path.join(config_dir, "config.bd")
    ref_file_path = os.path.join(config_dir, "output.bin")
    app_file_path = os.path.join(config_dir, app_name)
    with use_working_directory(tmpdir):
        converted_config = os.path.join(tmpdir, "config.yaml")
        cmd = [
            "hab",
            "convert",
            "--command",
            command_file_path,
            "--output",
            converted_config,
            app_file_path,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(converted_config)
        # assert load_binary(ref_file_path) == load_binary(output_file_path)

        output_file_path = os.path.join(tmpdir, "image_output.bin")
        cmd = [
            "hab",
            "export",
            "--command",
            converted_config,
            "--output",
            output_file_path,
            app_file_path,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(output_file_path)
        assert load_binary(ref_file_path) == load_binary(output_file_path)


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
def test_nxpimage_hab_parse(
    cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, source_bin, segments
):
    config_dir = os.path.join(hab_data_dir, "parse", configuration)
    source_bin_path = os.path.join(config_dir, source_bin)
    with use_working_directory(tmpdir):
        cmd = ["hab", "parse", "--binary", source_bin_path, "-o", str(tmpdir)]
        cli_runner.invoke(nxpimage.main, cmd)
        for segment in segments:
            segment_file_name = f"{segment}.bin"
            segment_file_path = os.path.join(tmpdir, segment_file_name)
            assert os.path.isfile(segment_file_path)
            assert filecmp.cmp(
                os.path.join(config_dir, segment_file_name),
                segment_file_path,
                shallow=False,
            )


def test_nxpimage_hab_export_secret_key_generated(cli_runner: CliRunner, tmpdir, hab_data_dir):
    config_dir = os.path.join(hab_data_dir, "export", "rt1165_semcnand_encrypted_random")
    with use_working_directory(tmpdir):
        copytree(config_dir, tmpdir, dirs_exist_ok=True)
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(
            cli_runner,
            output_file_path,
            os.path.join(tmpdir, "config.bd"),
            os.path.join(tmpdir, "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        )
        assert os.path.isfile(output_file_path)
        secret_key_path = os.path.join(
            tmpdir, "gen_hab_encrypt", "evkmimxrt1064_iled_blinky_SDRAM_hab_dek.bin"
        )
        assert os.path.isfile(secret_key_path)
        secret_key = load_binary(secret_key_path)
        assert len(secret_key) == 32
