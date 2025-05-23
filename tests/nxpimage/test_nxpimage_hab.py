#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
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
from spsdk.image.hab.hab_image import HabImage
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner
from tests.misc import GetPassMock


@pytest.fixture()
def hab_data_dir(data_dir):
    return os.path.join(data_dir, "hab")


def export_hab_cli(cli_runner: CliRunner, output_path: str, config_path: str):
    cmd = ["hab", "export", "--config", config_path, "--output", output_path, "--force"]

    cli_runner.invoke(nxpimage.main, cmd)


@pytest.mark.parametrize(
    "configuration",
    [
        "rt1160_xip_mdk_unsigned",
        "rt1170_QSPI_flash_unsigned",
        "rt1170_RAM_non_xip_unsigned",
        "rt1170_RAM_unsigned",
        "rt1170_flashloader_unsigned",
        "rt1170_RAM_unsigned_xmcd",
    ],
)
def test_nxpimage_hab_export_unsigned(cli_runner: CliRunner, tmpdir, hab_data_dir, configuration):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    with use_working_directory(tmpdir):
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(
            cli_runner,
            output_file_path,
            os.path.join(config_dir, "config.yaml"),
        )
        assert os.path.isfile(output_file_path)
        ref_binary = load_binary(os.path.join(config_dir, "output.bin"))
        new_binary = load_binary(output_file_path)
        assert len(ref_binary) == len(new_binary)
        assert ref_binary == new_binary


@patch("spsdk.crypto.keys.getpass", GetPassMock("test"))
@pytest.mark.parametrize(
    "configuration, config_files",
    [
        ("rt1040_srk_revoke_uid", ["config.yaml"]),
        ("rt1040_srk_revoke_command", ["config.yaml"]),
        (
            "rt1050_xip_image_iar_authenticated",
            [
                "config_pk_encrypted.yaml",
                "config_sp.yaml",
                "config_pk.yaml",
                "config_pk_simplified.yaml",
            ],
        ),
        ("rt1060_flashloader_authenticated_nocak", ["config.yaml"]),
        ("rt1160_RAM_encrypted", ["config.yaml"]),
        ("rt1165_flashloader_authenticated", ["config.yaml"]),
        ("rt1165_semcnand_authenticated", ["config.yaml"]),
        ("rt1165_semcnand_encrypted", ["config.yaml"]),
        ("rt1170_flashloader_authenticated", ["config.yaml"]),
        ("rt1170_RAM_authenticated", ["config.yaml"]),
        ("rt1170_semcnand_authenticated", ["config.yaml"]),
    ],
)
def test_nxpimage_hab_export_authenticated_rsa(
    cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, config_files
):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    for config_file in config_files:
        with use_working_directory(tmpdir):
            output_file_path = os.path.join(tmpdir, "image_output.bin")
            export_hab_cli(
                cli_runner,
                output_file_path,
                os.path.join(config_dir, config_file),
            )
            assert os.path.isfile(output_file_path)
            ref_binary = load_binary(os.path.join(config_dir, "output.bin"))
            new_binary = load_binary(output_file_path)
            assert len(ref_binary) == len(new_binary)
            assert ref_binary == new_binary


@patch("spsdk.crypto.keys.getpass", GetPassMock("test"))
@pytest.mark.parametrize(
    "config_file",
    ["config_pk_encrypted.yaml", "config_pk.yaml", "config_sp.yaml"],
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
    )
    assert os.path.isfile(output_file_path)
    hab = HabImage.parse(load_binary(output_file_path), FamilyRevision("mimxrt1173"))
    assert hab.app_segment
    assert hab.bdt_segment
    assert hab.csf_segment
    assert not hab.dcd_segment
    assert not hab.xmcd_segment
    assert len(hab.csf_segment.commands) == 6


@pytest.mark.parametrize(
    "configuration, app_name",
    [
        (
            "rt1160_xip_mdk_unsigned",
            "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.srec",
        ),
        (
            "rt1170_QSPI_flash_unsigned",
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.s19",
        ),
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
        ("rt1060_flashloader_authenticated_nocak", "flashloader.srec"),
        ("rt1165_semcnand_authenticated", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        ("rt1165_flashloader_authenticated", "flashloader.srec"),
        ("rt1165_semcnand_encrypted", "evkmimxrt1064_iled_blinky_SDRAM.s19"),
        (
            "rt1160_RAM_encrypted",
            "validationboard_imxrt1160_iled_blinky_cm7_int_RAM.s19",
        ),
    ],
)
def test_nxpimage_hab_convert(cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, app_name):
    config_dir = os.path.join(hab_data_dir, "export", configuration)
    tmp_config_dir = os.path.join(tmpdir, configuration)
    shutil.copytree(config_dir, tmp_config_dir, dirs_exist_ok=True)
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
    command_file_path = os.path.join(config_dir, "config.bd")
    ref_file_path = os.path.join(config_dir, "output.bin")
    app_file_path = os.path.join(config_dir, app_name)
    with use_working_directory(tmpdir):
        converted_config = os.path.join(tmp_config_dir, "config.yaml")
        cmd = [
            "hab",
            "convert",
            "--command",
            command_file_path,
            "--output",
            converted_config,
            app_file_path,
            "--force",
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(converted_config)

        output_file_path = os.path.join(tmpdir, "image_output.bin")
        export_hab_cli(cli_runner, output_file_path, converted_config)
        assert os.path.isfile(output_file_path)
        assert load_binary(ref_file_path) == load_binary(output_file_path)


@pytest.mark.parametrize(
    "configuration, family, segments",
    [
        (
            "rt1170_RAM_unsigned",
            FamilyRevision("mimxrt1176"),
            ["ivt", "bdt", "app"],
        ),
        (
            "rt1050_ext_xip_unsigned",
            FamilyRevision("mimxrt1050"),
            ["ivt", "bdt", "app"],
        ),
    ],
)
def test_nxpimage_hab_parse(
    cli_runner: CliRunner, tmpdir, hab_data_dir, configuration, family, segments
):
    config_dir = os.path.join(hab_data_dir, "parse", configuration)
    source_bin_path = os.path.join(config_dir, "hab_container.bin")
    with use_working_directory(tmpdir):
        cmd = [
            "hab",
            "parse",
            "--binary",
            source_bin_path,
            "--family",
            family.name,
            "--output",
            str(tmpdir),
        ]
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
    tmp_config_dir = os.path.join(tmpdir, "rt1165_semcnand_encrypted_random")
    with use_working_directory(tmpdir):
        copytree(config_dir, tmp_config_dir, dirs_exist_ok=True)
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
            os.path.join(tmp_config_dir, "config.yaml"),
        )
        assert os.path.isfile(output_file_path)
        secret_key_path = os.path.join(
            tmp_config_dir, "gen_hab_encrypt", "evkmimxrt1064_iled_blinky_SDRAM_hab_dek.bin"
        )
        assert os.path.isfile(secret_key_path)
        secret_key = load_binary(secret_key_path)
        assert len(secret_key) == 32


def test_nxpimage_hab_template_cli(cli_runner: CliRunner, tmpdir):
    template = os.path.join(tmpdir, "hab_template.yaml")
    cmd = [
        "hab",
        "get-template",
        "-f",
        "mimxrt1050",
        "--output",
        template,
    ]
    cli_runner.invoke(nxpimage.main, cmd)
    assert os.path.isfile(template)
