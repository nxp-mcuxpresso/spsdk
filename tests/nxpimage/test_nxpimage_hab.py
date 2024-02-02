#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test nxpimage HAB container CLI."""
import filecmp
import os
import shutil
from shutil import copytree
from unittest.mock import patch

import pytest

from spsdk.apps import nxpimage
from spsdk.image.hab.hab_container import HabContainer
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner
from tests.misc import GetPassMock


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
    ],
)
def test_nxpimage_hab_export_unsigned(
    cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, app_name
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
        assert ref_binary == new_binary


@patch("spsdk.crypto.keys.getpass", GetPassMock)
@pytest.mark.parametrize(
    "config_file",
    ["config_pk_encrypted.bd", "config_pk.bd", "config_sp.bd", "config_pk_autodetect.bd"],
)
@pytest.mark.parametrize(
    "configuration, app_name",
    [
        ("rt1050_xip_image_iar_authenticated", "led_blinky_xip_srec_iar.srec"),
        ("rt1160_RAM_encrypted", "validationboard_imxrt1160_iled_blinky_cm7_int_RAM.s19"),
        ("rt1165_flashloader_authenticated", "flashloader.srec"),
        ("rt1165_semcnand_authenticated", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        ("rt1165_semcnand_encrypted", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        ("rt1170_flashloader_authenticated", "flashloader.srec"),
        ("rt1170_RAM_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19"),
        ("rt1170_semcnand_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19"),
    ],
)
def test_nxpimage_hab_export_authenticated_rsa(
    cli_runner: CliRunner, tmpdir, config_file, hab_data_dir, configuration, app_name
):
    GetPassMock.PASSWORD = "test"
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    with use_working_directory(tmpdir):
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(
            cli_runner,
            output_file_path,
            os.path.join(config_dir, config_file),
            os.path.join(config_dir, app_name),
        )
        assert os.path.isfile(output_file_path)
        ref_binary = load_binary(os.path.join(config_dir, "output.bin"))
        new_binary = load_binary(output_file_path)
        assert len(ref_binary) == len(new_binary)
        assert ref_binary == new_binary


@patch("spsdk.crypto.keys.getpass", GetPassMock)
@pytest.mark.parametrize(
    "config_file",
    ["config_pk_encrypted.bd", "config_pk.bd", "config_sp.bd", "config_pk_autodetect.bd"],
)
def test_nxpimage_hab_export_authenticated_ecc(
    cli_runner: CliRunner, tmpdir, config_file, hab_data_dir
):
    """
    The image signed with ECC keys can not be verified as binary compare.
    The signature length may change and therefore the data reference in CSF commands may change.
    """
    config_dir = os.path.join(hab_data_dir, "export", "rt1173_flashloader_authenticated_ecc")
    output_file_path = os.path.join(tmpdir, "image_output.bin")
    export_hab_cli(
        cli_runner,
        output_file_path,
        os.path.join(config_dir, config_file),
        os.path.join(config_dir, "flashloader.srec"),
    )
    assert os.path.isfile(output_file_path)
    hab = HabContainer.parse(load_binary(output_file_path))
    assert hab.app_segment
    assert hab.bdt_segment
    assert hab.csf_segment
    assert not hab.dcd_segment
    assert not hab.xmcd_segment
    assert len(hab.csf_segment.segment.commands) == 6


@pytest.mark.parametrize(
    "configuration, app_name, config_file",
    [
        (
            "rt1160_xip_mdk_unsigned",
            "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.srec",
            "config.bd",
        ),
        (
            "rt1170_QSPI_flash_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.s19",
            "config.bd",
        ),
        (
            "rt1170_RAM_non_xip_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.s19",
            "config.bd",
        ),
        ("rt1170_RAM_unsigned", "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.s19", "config.bd"),
        ("rt1170_flashloader_unsigned", "evkmimxrt1170_flashloader.srec", "config.bd"),
        ("rt1170_flashloader_authenticated", "flashloader.srec", "config_sp.bd"),
        ("rt1170_RAM_authenticated", "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19", "config_sp.bd"),
        ("rt1050_xip_image_iar_authenticated", "led_blinky_xip_srec_iar.srec", "config_sp.bd"),
        (
            "rt1170_semcnand_authenticated",
            "evkmimxrt1170_iled_blinky_cm7_int_RAM.s19",
            "config_sp.bd",
        ),
        ("rt1165_semcnand_authenticated", "evkmimxrt1064_iled_blinky_SDRAM.s19", "config_sp.bd"),
        ("rt1165_flashloader_authenticated", "flashloader.srec", "config_sp.bd"),
        ("rt1165_semcnand_encrypted", "evkmimxrt1064_iled_blinky_SDRAM.s19", "config_sp.bd"),
        (
            "rt1160_RAM_encrypted",
            "validationboard_imxrt1160_iled_blinky_cm7_int_RAM.s19",
            "config_sp.bd",
        ),
    ],
)
def test_nxpimage_hab_convert(
    cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, app_name, config_file
):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    shutil.copytree(config_dir, tmpdir, dirs_exist_ok=True)
    shutil.copytree(
        os.path.join(hab_data_dir, "export", "keys"),
        os.path.join(tmpdir, "keys"),
        dirs_exist_ok=True,
    )
    shutil.copytree(
        os.path.join(hab_data_dir, "export", "crts"),
        os.path.join(tmpdir, "crts"),
        dirs_exist_ok=True,
    )
    command_file_path = os.path.join(config_dir, config_file)
    ref_file_path = os.path.join(config_dir, "output.bin")
    app_file_path = os.path.join(config_dir, app_name)
    with use_working_directory(tmpdir):
        converted_config = os.path.join(tmpdir, "config", "config.yaml")
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
    "configuration, segments",
    [
        (
            "rt1170_RAM_unsigned",
            ["ivt", "bdt", "app"],
        ),
        (
            "rt1050_ext_xip_unsigned",
            ["ivt", "bdt", "app"],
        ),
    ],
)
def test_nxpimage_hab_parse(cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, segments):
    config_dir = os.path.join(hab_data_dir, "parse", configuration)
    source_bin_path = os.path.join(config_dir, "hab_container.bin")
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


@pytest.mark.parametrize(
    "configuration",
    [
        "rt1050_xip_image_iar_authenticated",
        "rt1165_flashloader_authenticated",
        "rt1165_semcnand_authenticated",
        "rt1170_flashloader_authenticated",
        "rt1170_RAM_authenticated",
        "rt1170_semcnand_authenticated",
        "rt1160_xip_mdk_unsigned",
        "rt1170_RAM_non_xip_unsigned",
        "rt1170_flashloader_unsigned",
        "rt1170_QSPI_flash_unsigned",
        "rt1170_RAM_unsigned",
    ],
)
def test_nxpimage_hab_parse_and_export(configuration, hab_data_dir):
    ref_hab_file = os.path.join(hab_data_dir, "export", configuration, "output.bin")
    ref_hab = load_binary(ref_hab_file)
    hab = HabContainer.parse(ref_hab)
    assert hab.export() == ref_hab


def test_nxpimage_hab_export_secret_key_generated(cli_runner: CliRunner, tmpdir, hab_data_dir):
    config_dir = os.path.join(hab_data_dir, "export", "rt1165_semcnand_encrypted_random")
    with use_working_directory(tmpdir):
        copytree(config_dir, tmpdir, dirs_exist_ok=True)
        copytree(
            os.path.join(hab_data_dir, "export", "keys"),
            os.path.join(tmpdir, "keys"),
            dirs_exist_ok=True,
        )
        copytree(
            os.path.join(hab_data_dir, "export", "crts"),
            os.path.join(tmpdir, "crts"),
            dirs_exist_ok=True,
        )
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
