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

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory


@pytest.mark.parametrize(
    "command_file, externals, ref_file",
    [
        (
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.bd",
            ["evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.s19"],
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.bin",
        ),
        (
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.bd",
            ["evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.s19"],
            "evkmimxrt1170_iled_blinky_cm7_QSPI_FLASH_unsigned.bin",
        ),
        (
            "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.bd",
            ["evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.srec"],
            "evkbimxrt1160_iled_blinky_cm7_xip_mdk_unsigned.bin",
        ),
        (
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.bd",
            ["evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.s19"],
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.bin",
        ),
        (
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.bd",
            ["evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.s19"],
            "evkmimxrt1170_iled_blinky_cm7_int_RAM_non_xip_unsigned.bin",
        ),
        (
            "evkmimxrt1170_flashloader.bd",
            ["evkmimxrt1170_flashloader.srec"],
            "evkmimxrt1170_flashloader.bin",
        ),
    ],
)
def test_nxpimage_hab_export(tmpdir, data_dir, command_file, externals, ref_file):
    test_data_dir = os.path.join(data_dir, "hab")
    command_file_path = os.path.join(test_data_dir, command_file)
    runner = CliRunner()
    with use_working_directory(tmpdir):
        output_file_path = os.path.join(tmpdir, "image_output.bin")
        cmd = f"hab export --command {command_file_path} --output {output_file_path}"
        for external in externals:
            ext_path = os.path.join(test_data_dir, external)
            cmd = f"{cmd} {ext_path}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(output_file_path)

        ref_file_path = os.path.join(test_data_dir, ref_file)
        encrypted_image_enc = load_binary(ref_file_path)
        encrypted_nxpimage = load_binary(output_file_path)
        assert encrypted_image_enc == encrypted_nxpimage


@pytest.mark.parametrize(
    "source_bin, segments",
    [
        ("evkmimxrt1170_iled_blinky_cm7_int_RAM_unsigned.bin", ["ivt", "bdt", "app"]),
    ],
)
def test_nxpimage_hab_parse(tmpdir, data_dir, source_bin: str, segments):
    test_data_dir = os.path.join(data_dir, "hab")
    source_bin_path = os.path.join(test_data_dir, source_bin)
    runner = CliRunner()
    with use_working_directory(tmpdir):
        cmd = f"hab parse --binary {source_bin_path} {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        ref_output_dir = os.path.join(test_data_dir, source_bin.split(".")[0])
        for segment in segments:
            segment_file_name = f"{segment}.bin"
            segment_file_path = os.path.join(tmpdir, segment_file_name)
            assert os.path.isfile(segment_file_path)
            assert filecmp.cmp(
                os.path.join(ref_output_dir, segment_file_name),
                segment_file_path,
                shallow=False,
            )
