#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test SecureBinary part of nxpimage app."""
import json
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.crypto.exceptions import SPSDKKeysNotMatchingError
from spsdk.crypto.keys import PrivateKeyEcc
from spsdk.sbfile.sb31.images import SecureBinary31, SecureBinary31Header
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner


def process_config_file(config_path: str, destination: str):
    config_data = load_configuration(config_path)
    for key in config_data:
        if isinstance(config_data[key], str):
            config_data[key] = config_data[key].replace("\\", "/")
    ref_binary = config_data.get("containerOutputFile")
    new_binary = f"{destination}/{os.path.basename(ref_binary)}"
    new_config = f"{destination}/{os.path.basename(config_path)}"
    config_data["containerOutputFile"] = new_binary
    with open(new_config, "w") as f:
        json.dump(config_data, f, indent=2)
    return ref_binary, new_binary, new_config


def get_signing_key(config_file) -> PrivateKeyEcc:
    config_data = load_configuration(config_file)
    private_key_file = config_data.get(
        "signPrivateKey",
        config_data.get(
            "mainRootCertPrivateKeyFile",
            config_data.get("signingCertificatePrivateKeyFile"),
        ),
    )
    if not private_key_file:
        private_key_file = config_data.get("signProvider").split("=")[2]
    return PrivateKeyEcc.load(private_key_file.replace("\\", "/"))


def get_isk_key(config_file) -> PrivateKeyEcc:
    config_data = load_configuration(config_file)
    private_key_file = config_data.get(
        "signPrivateKey", config_data.get("mainRootCertPrivateKeyFile")
    )
    if not private_key_file:
        private_key_file = config_data.get("signProvider").split("=")[2]
    return PrivateKeyEcc.load(private_key_file.replace("\\", "/"))


@pytest.mark.parametrize(
    "config_file,device",
    [
        ("sb3_256_256.yaml", "lpc55s3x"),
        ("sb3_256_none.yaml", "lpc55s3x"),
        ("sb3_256_none_ernad.yaml", "lpc55s3x"),
        ("sb3_384_256.yaml", "lpc55s3x"),
        ("sb3_384_256_fixed_timestamp.yaml", "lpc55s3x"),
        ("sb3_384_256_unencrypted.yaml", "lpc55s3x"),
        ("sb3_384_384.yaml", "lpc55s3x"),
        ("sb3_384_none.yaml", "lpc55s3x"),
        ("sb3_test_384_384_unencrypted.yaml", "lpc55s3x"),
        ("sb3_256_256.yaml", "mcxn9xx"),
        ("sb3_256_none.yaml", "mcxn9xx"),
        ("sb3_384_256.yaml", "mcxn9xx"),
        ("sb3_384_256_fixed_timestamp.yaml", "mcxn9xx"),
        ("sb3_384_256_unencrypted.yaml", "mcxn9xx"),
        ("sb3_384_384.yaml", "mcxn9xx"),
        ("sb3_384_none.yaml", "mcxn9xx"),
        ("sb3_384_none_keyblob.yaml", "mcxn9xx"),
        ("sb3_test_384_384_unencrypted.yaml", "mcxn9xx"),
        ("sb3_test_384_384_unencrypted.yaml", "kw45xx"),
        ("sb3_384_384.yaml", "kw45xx"),
        ("sb3_384_none.yaml", "kw45xx"),
        ("sb3_test_384_384_unencrypted.yaml", "k32w1xx"),
        ("sb3_384_384.yaml", "k32w1xx"),
        ("sb3_384_none.yaml", "k32w1xx"),
    ],
)
def test_nxpimage_sb31(cli_runner: CliRunner, nxpimage_data_dir, tmpdir, config_file, device):
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)
        cmd = f"sb31 export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        sb31 = SecureBinary31.load_from_config(
            config=load_configuration(config_file),
            search_paths=[f"{nxpimage_data_dir}/workspace/cfgs/{device}", str(tmpdir)],
        )

        # Validate data part
        signature_offset = (
            SecureBinary31Header.HEADER_SIZE
            + len(sb31.sb_commands.final_hash)
            + sb31.cert_block.expected_size
        )
        header_part_size = signature_offset
        data_blocks_offset = (
            SecureBinary31Header.HEADER_SIZE
            + len(sb31.sb_commands.final_hash)
            + sb31.cert_block.expected_size
            + sb31.signature_provider.signature_length
        )
        if sb31.cert_block.isk_certificate:
            header_part_size -= len(sb31.cert_block.isk_certificate.signature)

        ref_data = load_binary(ref_binary)
        new_data = load_binary(new_binary)
        assert ref_data[:header_part_size], new_data[:header_part_size]
        assert ref_data[data_blocks_offset:], new_data[data_blocks_offset:]
        signing_key = get_signing_key(config_file)

        # Validate signature
        assert signing_key.get_public_key().verify_signature(
            new_data[signature_offset:data_blocks_offset],
            new_data[:signature_offset],
        )
        assert signing_key.get_public_key().verify_signature(
            ref_data[signature_offset:data_blocks_offset],
            ref_data[:signature_offset],
        )

        # ISK signature won't be checked - is already checked in MBI tests


def test_nxpimage_sb31_notime(cli_runner: CliRunner, nxpimage_data_dir, tmpdir):
    config_file = "sb3_256_256.yaml"
    device = "lpc55s3x"
    with use_working_directory(nxpimage_data_dir):
        config_file = f"{nxpimage_data_dir}/workspace/cfgs/{device}/{config_file}"
        ref_binary, new_binary, new_config = process_config_file(config_file, tmpdir)
        cmd = f"sb31 export -c {new_config}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(new_binary)

        # Since there's a new timestamp, compare only portions of files
        with open(ref_binary, "rb") as f:
            ref_data = f.read()
        with open(new_binary, "rb") as f:
            new_data = f.read()

        assert len(ref_data) == len(new_data)
        assert ref_data[:20] == new_data[:20]
        assert ref_data[0x1C:0x3C] == new_data[0x1C:0x3C]


def test_nxpimage_sb31_kaypair_not_matching(nxpimage_data_dir):
    config_file = f"{nxpimage_data_dir}/workspace/cfgs/lpc55s3x/sb3_256_256_keys_dont_match.yaml"
    sb31 = SecureBinary31.load_from_config(
        config=load_configuration(config_file),
        search_paths=[f"{nxpimage_data_dir}/workspace/cfgs/lpc55s3x", nxpimage_data_dir],
    )
    with pytest.raises(SPSDKKeysNotMatchingError):
        sb31.export()
