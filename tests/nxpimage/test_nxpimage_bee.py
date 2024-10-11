#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python(tmpdir
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test BEE part of nxpimage app."""
import os
import shutil

import pytest

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner

INPUT_BINARY = "evkbimxrt1050_iled_blinky_ext_FLASH_unencrypted_nopadding.bin"


@pytest.mark.parametrize(
    "case, config, reference, engines",
    [
        (
            "both_engines_ctr",
            "bee_config.yaml",
            "evkbimxrt1050_iled_blinky_ext_FLASH_bootable_nopadding.bin",
            [0, 1],
        ),
        ("both_engines_generated_header", "bee_config.yaml", None, [0, 1]),
        ("one_engine_generated_header", "bee_config.yaml", None, [0]),
    ],
)
def test_nxpimage_bee(cli_runner: CliRunner, tmpdir, data_dir, case, config, reference, engines):
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        config_dict = load_configuration(config)
        out_dir = os.path.join(work_dir, config_dict["output_folder"])
        cmd = f"bee export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(os.path.join(out_dir, "encrypted.bin"))
        for engine in engines:
            assert os.path.isfile(os.path.join(out_dir, f"bee_ehdr{engine}.bin"))
        if reference:
            encrypted_image_enc = load_binary(reference)
            encrypted_nxpimage = load_binary(os.path.join(out_dir, "encrypted.bin"))
            assert encrypted_image_enc == encrypted_nxpimage


@pytest.mark.parametrize(
    "case, config",
    [
        ("both_engines_generated_header_overlap", "bee_config.yaml"),
    ],
)
def test_nxpimage_bee_overlap(cli_runner: CliRunner, tmpdir, data_dir, case, config):
    work_dir = os.path.join(tmpdir, "bee", case)
    shutil.copytree(os.path.join(data_dir, "bee", case), work_dir)
    shutil.copy(os.path.join(data_dir, "bee", INPUT_BINARY), work_dir)
    with use_working_directory(work_dir):
        cmd = f"bee export -c {config}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=-1)


@pytest.mark.parametrize(
    "family",
    [
        ("rt1015"),
        ("rt102x"),
        ("rt105x"),
        ("rt106x"),
    ],
)
def test_nxpimage_bee_template_cli(cli_runner: CliRunner, tmpdir, family):
    template = os.path.join(tmpdir, "bee_template.yaml")
    cmd = f"bee get-template -f {family} -o {template}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(template)
