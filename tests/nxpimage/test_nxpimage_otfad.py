#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test OTFAD part of nxpimage app."""
import os
import shutil

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_configuration, use_working_directory


@pytest.mark.parametrize(
    "config",
    [
        ("otfad_rt5xx.yaml"),
        ("otfad_rt6xx.yaml"),
    ],
)
def test_nxpimage_otfad_export(tmpdir, data_dir, config):
    runner = CliRunner()
    work_dir = os.path.join(tmpdir, "otfad")
    shutil.copytree(os.path.join(data_dir, "otfad"), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"otfad export {config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(out_dir, "KeyBlob0_data_encrypted.bin"))
        assert os.path.isfile(os.path.join(out_dir, "KeyBlob1_data.bin"))
        assert os.path.isfile(os.path.join(out_dir, "KeyBlob2_data_encrypted.bin"))
        assert os.path.isfile(os.path.join(out_dir, "OTFAD_Table.bin"))
        assert os.path.isfile(os.path.join(out_dir, "otfad_whole_image.bin"))
        assert os.path.isfile(os.path.join(out_dir, "readme.txt"))
        assert os.path.isfile(os.path.join(out_dir, "sb21_otfad_example.bd"))


@pytest.mark.parametrize(
    "omk,ok,family",
    [
        ("", "", "rt5xx"),
        ("", "000102030405060708090a0b0c0d0e0f", "rt5xx"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "", "rt5xx"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "rt5xx",
        ),
        ("otp_master_key.bin", "", "rt5xx"),
        ("", "otfad_key.bin", "rt5xx"),
        ("otp_master_key.bin", "otfad_key.bin", "rt5xx"),
        ("otp_master_key.txt", "", "rt5xx"),
        ("", "otfad_key.txt", "rt5xx"),
        ("otp_master_key.txt", "otfad_key.txt", "rt5xx"),
        ("", "", "rt6xx"),
        ("", "000102030405060708090a0b0c0d0e0f", "rt6xx"),
        ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "", "rt6xx"),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "rt6xx",
        ),
        ("otp_master_key.bin", "", "rt6xx"),
        ("", "otfad_key.bin", "rt6xx"),
        ("otp_master_key.bin", "otfad_key.bin", "rt6xx"),
        ("otp_master_key.txt", "", "rt6xx"),
        ("", "otfad_key.txt", "rt6xx"),
        ("otp_master_key.txt", "otfad_key.txt", "rt6xx"),
    ],
)
def test_nxpimage_otfad_kek_cli(tmpdir, data_dir, omk, ok, family):
    runner = CliRunner()
    with use_working_directory(os.path.join(data_dir, "otfad")):
        cmd = f"otfad get-kek {'-m '+ omk if omk else ''} {'-k '+ ok if ok else ''} -f {family} -o {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0

        assert os.path.isfile(os.path.join(tmpdir, "otfad_kek.bin"))
        assert os.path.isfile(os.path.join(tmpdir, "otfad_kek.txt"))


@pytest.mark.parametrize(
    "family",
    [
        ("rt5xx"),
        ("rt6xx"),
    ],
)
def test_nxpimage_otfad_template_cli(tmpdir, family):
    runner = CliRunner()
    template = os.path.join(tmpdir, "otfad_template.yaml")
    cmd = f"otfad get-template -f {family} {template}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(template)
