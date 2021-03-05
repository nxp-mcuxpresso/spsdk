#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of elftosb app."""
import os
import filecmp
import json

import pytest
from click.testing import CliRunner

from spsdk.apps import elftosb
from spsdk.utils.misc import use_working_directory
from spsdk.image import MasterBootImageN4Analog, MasterBootImageType


def process_config_file(config_path: str, destination: str):
    with open(config_path) as f:
        config_data = json.load(f)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace('\\', '/')
    ref_binary = config_data['masterBootOutputFile']
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/new_config.json"
    config_data['masterBootOutputFile'] = new_binary
    with open(new_config, 'w') as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


@pytest.mark.parametrize(
    "config_file",
    [
        "mb_ram_crc.json", "mb_ram_crc_version.json", "mb_xip_crc.json"
    ]
)
def test_elftosb_mbi_basic(data_dir, tmpdir, config_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(new_binary, ref_binary)


@pytest.mark.parametrize(
    "config_file",
    [
        "mb_xip_256_none.json", "mb_xip_384_256.json", "mb_xip_384_384.json"
    ]

)
def test_elftosb_mbi_signed(data_dir, tmpdir, config_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)

        cmd = f"--image-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        assert os.path.isfile(new_binary)
        # assert filecmp.cmp(new_binary, ref_binary)


def test_elftosb_mbi_lower(data_dir):
    mbi = MasterBootImageN4Analog(
        app=bytes(100), load_addr=0, image_type=MasterBootImageType.PLAIN_IMAGE
    )
    assert mbi.data

    mbi = MasterBootImageN4Analog(
        app=bytes(100), load_addr=0
    )
    assert mbi.data
    assert mbi.info()
    assert mbi.export()
