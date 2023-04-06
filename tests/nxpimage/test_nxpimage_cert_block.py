#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Certification block part of nxpimage app."""
import json
import os
from typing import Tuple

from click.testing import CliRunner

from spsdk.apps import nxpimage


def process_config_file(
    config_path: str, destination: str, config_member: str
) -> Tuple[str, str, str]:
    with open(config_path) as f:
        config_data = json.load(f)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data[config_member]
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/new_config.json"
    config_data[config_member] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def test_nxpimage_cert_block_get_template(tmpdir):
    out_file = f"{tmpdir}/cert_block_template.yaml"
    runner = CliRunner()
    cmd = f"cert-block get-template {out_file}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(out_file)


def test_nxpimage_cert_block_parse(elftosb_data_dir, tmpdir):
    out_folder = tmpdir
    input_file = os.path.join(
        elftosb_data_dir, "workspace", "output_images", "lpc55s3x", "cert_384_256.bin"
    )
    runner = CliRunner()
    cmd = f"cert-block parse -b {input_file} {out_folder}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(os.path.join(out_folder, "cert_block_config.yaml"))
    assert os.path.isfile(os.path.join(out_folder, "rootCertificate0File.pub"))
    assert os.path.isfile(os.path.join(out_folder, "signingCertificateFile.pub"))
