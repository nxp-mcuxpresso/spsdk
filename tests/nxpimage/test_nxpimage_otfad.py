#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test OTFAD part of nxpimage app."""
import filecmp
import os
import shutil

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.utils.crypto.otfad import OtfadNxp
from spsdk.utils.misc import load_configuration, load_text, use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "config",
    [
        ("otfad_rt5xx.yaml"),
        ("otfad_rt6xx.yaml"),
    ],
)
def test_nxpimage_otfad_export(cli_runner: CliRunner, tmpdir, data_dir, config):
    work_dir = os.path.join(tmpdir, "otfad")
    shutil.copytree(os.path.join(data_dir, "otfad"), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"otfad export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(out_dir, "encrypted_blobs.bin"))
        assert os.path.isfile(os.path.join(out_dir, "OTFAD_Table.bin"))
        assert os.path.isfile(os.path.join(out_dir, "otfad_whole_image.bin"))
        assert os.path.isfile(os.path.join(out_dir, "readme.txt"))
        assert os.path.isfile(os.path.join(out_dir, "sb21_otfad_example.bd"))


@pytest.mark.parametrize(
    "config,per_ix,blhost_bcf_res,bin_out,family",
    [
        (
            "otfad_rt1160.yaml",
            2,
            [
                "efuse-program-once 128 0xFFEEDDCC --no-verify",
                "efuse-program-once 129 0xBBAA9988 --no-verify",
                "efuse-program-once 130 0x77665544 --no-verify",
                "efuse-program-once 131 0x33221100 --no-verify",
                "efuse-program-once 71 0x20 --no-verify",
            ],
            "otfad_rt1160_out.bin",
            "rt116x",
        ),
        (
            "otfad_rt1170.yaml",
            2,
            [
                "efuse-program-once 128 0xFFEEDDCC --no-verify",
                "efuse-program-once 129 0xBBAA9988 --no-verify",
                "efuse-program-once 130 0x77665544 --no-verify",
                "efuse-program-once 131 0x33221100 --no-verify",
            ],
            "otfad_rt1170_out.bin",
            "rt117x",
        ),
        (
            "otfad_rt1180.yaml",
            2,
            [
                "efuse-program-once 178 0xFFEEDDCC --no-verify",
                "efuse-program-once 182 0x8 --no-verify",
            ],
            "otfad_rt1180_out.bin",
            "mimxrt1189",
        ),
        (
            "otfad_rt1180_no_encryption.yaml",
            2,
            [
                "efuse-program-once 178 0xFFEEDDCC --no-verify",
                "efuse-program-once 182 0x8 --no-verify",
            ],
            "otfad_rt1180_no_encryption_out.bin",
            "mimxrt1189",
        ),
        (
            "otfad_rt1180_txt.yaml",
            2,
            [
                "efuse-program-once 178 0xFFEEDDCC --no-verify",
                "efuse-program-once 182 0x8 --no-verify",
            ],
            "otfad_rt1180_out.bin",
            "mimxrt1189",
        ),
        (
            "otfad_rt1180_scramble.yaml",
            2,
            [
                "efuse-program-once 178 0xFFEEDDCC --no-verify",
                "efuse-program-once 182 0x7288 --no-verify",
                "efuse-program-once 183 0x78563412 --no-verify",
            ],
            "otfad_rt1180_scramble_out.bin",
            "mimxrt1189",
        ),
        (
            "otfad_rt1170_scramble.yaml",
            1,
            [
                "efuse-program-once 128 0xFFEEDDCC --no-verify",
                "efuse-program-once 129 0xBBAA9988 --no-verify",
                "efuse-program-once 130 0x77665544 --no-verify",
                "efuse-program-once 131 0x33221100 --no-verify",
                "efuse-program-once 71 0x3 --no-verify",
                "efuse-program-once 132 0x78563412 --no-verify",
                "efuse-program-once 133 0x72 --no-verify",
            ],
            "otfad_rt1170_scramble_out.bin",
            "rt117x",
        ),
        (
            "otfad_rt1010_scramble.yaml",
            1,
            [
                "efuse-program-once 41 0xFFEEDDCC --no-verify",
                "efuse-program-once 44 0x33221100 --no-verify",
                "efuse-program-once 35 0x572 --no-verify",
                "efuse-program-once 34 0x78563412 --no-verify",
            ],
            "otfad_rt1010_scramble_out.bin",
            "rt1010",
        ),
    ],
)
def test_nxpimage_otfad_export_rt11x0(
    cli_runner: CliRunner, tmpdir, data_dir, config, per_ix, blhost_bcf_res, bin_out, family
):
    work_dir = os.path.join(tmpdir, "otfad")
    shutil.copytree(os.path.join(data_dir, "otfad"), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"otfad export -i {per_ix} -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(out_dir, f"otfad{per_ix}_{family}.bcf"))
        assert os.path.isfile(os.path.join(out_dir, "encrypted_blobs.bin"))
        assert os.path.isfile(os.path.join(out_dir, "OTFAD_Table.bin"))
        assert os.path.isfile(os.path.join(out_dir, "otfad_whole_image.bin"))
        assert os.path.isfile(os.path.join(out_dir, "readme.txt"))

        blhost_script = load_text(f"otfad{per_ix}_{family}.bcf", search_paths=[out_dir])

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
def test_nxpimage_otfad_kek_cli(cli_runner: CliRunner, tmpdir, data_dir, omk, ok, family):
    with use_working_directory(os.path.join(data_dir, "otfad")):
        cmd = f"otfad get-kek {'-m '+ omk if omk else ''} {'-k '+ ok if ok else ''} -f {family} -o {tmpdir}"
        cli_runner.invoke(nxpimage.main, cmd.split())

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
                "efuse-program-once 112 0x1C1D1E1F --no-verify",
                "efuse-program-once 108 0x3020100 --no-verify",
            ],
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "000102030405060708090a0b0c0d0e0f",
            "rt6xx",
            [
                "efuse-program-once 112 0x1C1D1E1F --no-verify",
                "efuse-program-once 108 0x3020100 --no-verify",
            ],
        ),
    ],
)
def test_nxpimage_otfad_keys_blhost(omk, ok, family, results):
    blhost_script = OtfadNxp.get_blhost_script_otp_keys(
        family, otp_master_key=bytes.fromhex(omk), otfad_kek_seed=bytes.fromhex(ok)
    )
    assert len(blhost_script)
    for result in results:
        assert result in blhost_script


@pytest.mark.parametrize(
    "family",
    [
        ("rt5xx"),
        ("rt6xx"),
        ("rt1010"),
        ("rt116x"),
        ("rt117x"),
        ("mimxrt1189"),
    ],
)
def test_nxpimage_otfad_template_cli(cli_runner: CliRunner, tmpdir, family):
    template = os.path.join(tmpdir, "otfad_template.yaml")
    cmd = f"otfad get-template -f {family} --output {template}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(template)


@pytest.mark.parametrize(
    "config",
    [
        ("otfad_rt1170_custom_name.yaml"),
    ],
)
def test_otfad_custom_output(cli_runner: CliRunner, tmpdir, data_dir, config):
    work_dir = os.path.join(tmpdir, "otfad")
    shutil.copytree(os.path.join(data_dir, "otfad"), work_dir)

    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        config_dict["output_name"] = os.path.join(tmpdir, "otfad_output")
        config_dict["keyblob_name"] = "keyblob"
        config_dict["encrypted_name"] = ""

        modified_config = os.path.join(work_dir, "modified_config.yaml")
        with open(modified_config, "w") as f:
            yaml.dump(config_dict, f)
        cmd = f"otfad export -c {modified_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        assert os.path.isfile(os.path.join(out_dir, "keyblob.bin"))
        assert not os.path.isfile(os.path.join(out_dir, "readme.txt"))
        assert os.path.isfile(config_dict["output_name"] + ".bin")
