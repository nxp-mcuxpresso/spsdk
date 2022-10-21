#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test OTFAD part of nxpimage app."""
import filecmp
import os
import shutil

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.crypto.otfad import OtfadNxp
from spsdk.utils.misc import load_configuration, load_text, use_working_directory


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
        assert os.path.isfile(os.path.join(out_dir, "KeyBlob2_data.bin"))
        assert os.path.isfile(os.path.join(out_dir, "OTFAD_Table.bin"))
        assert os.path.isfile(os.path.join(out_dir, "otfad_whole_image.bin"))
        assert os.path.isfile(os.path.join(out_dir, "readme.txt"))
        assert os.path.isfile(os.path.join(out_dir, "sb21_otfad_example.bd"))


@pytest.mark.parametrize(
    "config,per_ix,blhost_bcf_res,bin_out",
    [
        (
            "otfad_rt1180.yaml",
            2,
            [
                "efuse-program-once 178 0xffeeddcc --no-verify",
                "efuse-program-once 182 0x00000008 --no-verify",
            ],
            "otfad_rt1180_out.bin",
        ),
        (
            "otfad_rt1180_txt.yaml",
            2,
            [
                "efuse-program-once 178 0xffeeddcc --no-verify",
                "efuse-program-once 182 0x00000008 --no-verify",
            ],
            "otfad_rt1180_out.bin",
        ),
        (
            "otfad_rt1180_scramble.yaml",
            2,
            [
                "efuse-program-once 178 0xffeeddcc --no-verify",
                "efuse-program-once 182 0x00007288 --no-verify",
                "efuse-program-once 183 0x78563412 --no-verify",
            ],
            "otfad_rt1180_scramble_out.bin",
        ),
    ],
)
def test_nxpimage_otfad_export_rt1180(tmpdir, data_dir, config, per_ix, blhost_bcf_res, bin_out):
    runner = CliRunner()
    work_dir = os.path.join(tmpdir, "otfad")
    shutil.copytree(os.path.join(data_dir, "otfad"), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"otfad export -i {per_ix} {config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(out_dir, f"otfad{per_ix}_rt1180_blhost.bcf"))
        assert os.path.isfile(os.path.join(out_dir, "KeyBlob0_data_encrypted.bin"))
        assert os.path.isfile(os.path.join(out_dir, "OTFAD_Table.bin"))
        assert os.path.isfile(os.path.join(out_dir, "otfad_whole_image.bin"))
        assert os.path.isfile(os.path.join(out_dir, "readme.txt"))

        blhost_script = load_text(f"otfad{per_ix}_rt1180_blhost.bcf", search_paths=[out_dir])

        for result in blhost_bcf_res:
            assert result in blhost_script

        assert filecmp.cmp(os.path.join(out_dir, "otfad_whole_image.bin"), bin_out, shallow=False)


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
    "omk,ok,family,results",
    [
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "rt5xx",
            [
                "efuse-program-once 112 0x1c1d1e1f --no-verify",
                "efuse-program-once 108 0x03020100 --no-verify",
            ],
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "rt6xx",
            [
                "efuse-program-once 112 0x1c1d1e1f --no-verify",
                "efuse-program-once 108 0x03020100 --no-verify",
            ],
        ),
    ],
)
def test_nxpimage_otfad_keys_blhost(omk, ok, family, results):
    blhost_script = OtfadNxp.get_blhost_script_otp_keys(
        family, otp_master_key=bytes.fromhex(omk), otfad_key_seed=bytes.fromhex(ok)
    )
    assert len(blhost_script)
    for result in results:
        assert result in blhost_script


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
