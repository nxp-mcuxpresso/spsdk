#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""
import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.image.ahab.ahab_container import AHABImage
from spsdk.image.ahab.signed_msg import SignedMessage
from spsdk.utils.misc import load_binary, use_working_directory
from tests.elftosb.test_elftosb_sb31 import process_config_file


@pytest.mark.parametrize(
    "config_file",
    [
        ("config_ctcm.json"),
    ],
)
def test_nxpimage_ahab_export(tmpdir, data_dir, config_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)
        assert filecmp.cmp(os.path.join(data_dir, "ahab", ref_binary), new_binary, shallow=False)


@pytest.mark.parametrize(
    "config_file",
    [
        ("ctcm_cm33_signed_img.json"),
        ("ctcm_cm33_signed_cert.yaml"),
        ("ctcm_cm33_signed_cert_nx.yaml"),
        ("ctcm_cm33_signed_cert_sb.yaml"),
        ("ctcm_cm33_encrypted_img.yaml"),
    ],
)
def test_nxpimage_ahab_export_signed_encrypted(tmpdir, data_dir, config_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"ahab export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)


def test_nxpimage_ahab_parse_cli(tmpdir, data_dir):
    runner = CliRunner()
    with use_working_directory(data_dir):
        cmd = f"ahab parse -f rt1180 -b ahab/mxrt1180a0-ahab-container.bin {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(tmpdir, "parsed_config.yaml"))


def test_nxpimage_ahab_parse(data_dir):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/mxrt1180a0-ahab-container.bin")
        ahab = AHABImage("rt1180", "a0")
        ahab.parse(original_file)
        ahab.update_fields()
        ahab.validate()
        exported_ahab = ahab.export()
        assert original_file == exported_ahab


@pytest.mark.parametrize(
    "config_file",
    [
        ("return_lc.yaml"),
    ],
)
def test_nxpimage_signed_message_export(tmpdir, data_dir, config_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        config_file = f"{data_dir}/ahab/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir, "output")
        cmd = f"signed-msg export {new_config}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(new_binary)
        assert os.path.getsize(ref_binary) == os.path.getsize(new_binary)

        new_bin = load_binary(new_binary)
        ref_bin = load_binary(ref_binary)
        # Check content up to signature
        assert new_bin[:408] == ref_bin[:408]


def test_nxpimage_signed_message_parse_cli(tmpdir, data_dir):
    runner = CliRunner()
    with use_working_directory(data_dir):
        cmd = f"signed-msg parse -f rt1180 -b ahab/signed_msg_oem_field_return.bin {tmpdir}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(os.path.join(tmpdir, "parsed_config.yaml"))


def test_nxpimage_signed_message_parse(data_dir):
    with use_working_directory(data_dir):
        original_file = load_binary(f"{data_dir}/ahab/signed_msg_oem_field_return.bin")
        signed_msg = SignedMessage().parse(original_file)
        signed_msg.update_fields()
        signed_msg.validate({})
        exported_signed_msg = signed_msg.export()
        assert original_file == exported_signed_msg
