#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test SecureBinary part of elftosb app."""
import json
import os
import filecmp
from typing import Tuple

import pytest
from click.testing import CliRunner

from spsdk.apps import elftosb, elftosb_helper
from spsdk.utils.misc import use_working_directory


def process_config_file(
        config_path: str, destination: str, config_member: str
) -> Tuple[str, str, str]:
    with open(config_path) as f:
        config_data = json.load(f)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace('\\', '/')
    ref_binary = config_data[config_member]
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/new_config.json"
    config_data[config_member] = new_binary
    with open(new_config, 'w') as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


@pytest.mark.parametrize(
    "config_file",
    [
        "sb3_256_256.json",
        "sb3_256_none.json",
        "sb3_256_none_ernad.json",
        "sb3_384_256.json",
        "sb3_384_256_fixed_timestamp.json",
        "sb3_384_256_unencrypted.json",
        "sb3_384_384.json",
        "sb3_384_none.json",
        "sb3_test_384_384_unencrypted.json",
    ]
)
def test_elftosb_sb31(data_dir, tmpdir, config_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "containerOutputFile")
        cmd = f"--container-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(ref_binary, new_binary, shallow=False)

def test_elftosb_sb31_notime(data_dir, tmpdir):

    config_file = "sb3_256_256.json"
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "containerOutputFile")
        cmd = f"--container-conf {new_config}"
        result = runner.invoke(elftosb.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)

        # Since there's a new timestamp, compare only portions of files        
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()
        
        assert len(ref_data) == len(new_data)
        assert ref_data[:20] == new_data[:20]
        assert ref_data[0x1c:0x3c] == new_data[0x1c:0x3c]

