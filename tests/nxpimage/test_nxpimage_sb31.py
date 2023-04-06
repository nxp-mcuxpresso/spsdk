#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test SecureBinary part of nxpimage app."""
import filecmp
import json
import os
from typing import Dict, Union

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import use_working_directory


def process_config_file(config_path: str, destination: str):
    with open(config_path) as f:
        config_data: Dict[str, Union[str, int]] = json.load(f)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data.get("containerOutputFile") or config_data.get("containerOutputFile")
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/{os.path.basename(config_path)}"
    config_data["containerOutputFile"] = new_binary
    # It doesn't matter that there will be both keys in this temporary config
    config_data["containerOutputFile"] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("sb3_256_256.json", "lpc55s3x"),
        ("sb3_256_none.json", "lpc55s3x"),
        ("sb3_256_none_ernad.json", "lpc55s3x"),
        ("sb3_384_256.json", "lpc55s3x"),
        ("sb3_384_256_fixed_timestamp.json", "lpc55s3x"),
        ("sb3_384_256_unencrypted.json", "lpc55s3x"),
        ("sb3_384_384.json", "lpc55s3x"),
        ("sb3_384_none.json", "lpc55s3x"),
        ("sb3_test_384_384_unencrypted.json", "lpc55s3x"),
    ],
)
def test_nxpimage_sb31(elftosb_data_dir, tmpdir, config_file, device):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)
        cmd = f"sb31 export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(ref_binary, new_binary, shallow=False)


@pytest.mark.parametrize(
    "sb31_cfg,cert_block_cfg,device",
    [
        ("sb3_256_256.json", "cert_256_256.json", "lpc55s3x"),
        ("sb3_384_256.json", "cert_384_256.json", "lpc55s3x"),
        ("sb3_384_384.json", "cert_384_384.json", "lpc55s3x"),
    ],
)
def test_nxpimage_sb31_cert_block(elftosb_data_dir, tmpdir, sb31_cfg, cert_block_cfg, device):
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        cert_cfg_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{cert_block_cfg}"
        sb31_cfg_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{sb31_cfg}"
        cert_ref_binary, cert_new_binary, cert_new_config = process_config_file(
            cert_cfg_file, tmpdir
        )
        sb31_ref_binary, sb31_new_binary, sb31_new_config = process_config_file(
            sb31_cfg_file, tmpdir
        )
        # Generate and verify certification block
        cmd = f"cert-block export {cert_new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(cert_new_binary)
        assert filecmp.cmp(cert_ref_binary, cert_new_binary, shallow=False)

        # Generate and verify SB31 with certification block
        cmd = f"sb31 export {sb31_new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(sb31_new_binary)
        assert filecmp.cmp(sb31_ref_binary, sb31_new_binary, shallow=False)


def test_nxpimage_sb31_notime(elftosb_data_dir, tmpdir):
    config_file = "sb3_256_256.json"
    device = "lpc55s3x"
    runner = CliRunner()
    with use_working_directory(elftosb_data_dir):
        config_file = f"{elftosb_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)
        cmd = f"sb31 export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)

        # Since there's a new timestamp, compare only portions of files
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()

        assert len(ref_data) == len(new_data)
        assert ref_data[:20] == new_data[:20]
        assert ref_data[0x1C:0x3C] == new_data[0x1C:0x3C]
