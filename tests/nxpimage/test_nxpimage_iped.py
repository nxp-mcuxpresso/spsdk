#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for IPED table commands in nxpimage application."""

import os
from typing import Any

import yaml

from spsdk.apps import nxpimage
from spsdk.image.iped.iped import Iped, IpedV1
from spsdk.utils.config import Config
from spsdk.utils.misc import load_binary, write_file
from tests.cli_runner import CliRunner


def _write_iped_v1_config(path: str, output_folder: str, family: str = "mimx943") -> None:
    """Write a minimal IPED V1 configuration file.

    :param path: Output configuration path.
    :param output_folder: IPED output folder.
    :param family: Target family.
    """
    config = {
        "family": family,
        "output_folder": output_folder,
        "output_name": "iped_config",
        "output_format": "bin",
        "fw_version": "0xAABBCCDD",
        "regions": [
            {
                "region_id": 4,
                "start_address": "0x28010000",
                "end_address": "0x28020000",
                "nonce": "0x0011223344556677",
            }
        ],
    }
    write_file(yaml.safe_dump(config), path)


def test_nxpimage_iped_export(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test IPED export CLI command with V1 config for mimx943."""
    config_path = os.path.join(tmpdir, "iped.yaml")
    output_folder = os.path.join(tmpdir, "out")
    _write_iped_v1_config(config_path, output_folder)

    cli_runner.invoke(nxpimage.main, ["iped", "export", "-c", config_path])

    output_file = os.path.join(output_folder, "iped_config.bin")
    assert os.path.isfile(output_file)
    exported = load_binary(output_file)
    assert len(exported) == 0x400
    # Verify V1 header tag in LE word: (Tag<<24|Len<<8|Ver) → tag at byte 3
    assert exported[3] == 0x4C


def test_nxpimage_iped_parse(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test IPED parse CLI command with V1 format for mimx943."""
    config_path = os.path.join(tmpdir, "iped.yaml")
    output_folder = os.path.join(tmpdir, "out")
    _write_iped_v1_config(config_path, output_folder)
    cli_runner.invoke(nxpimage.main, ["iped", "export", "-c", config_path])
    table_path = os.path.join(output_folder, "iped_config.bin")
    parsed_config_path = os.path.join(tmpdir, "parsed_iped.yaml")

    cli_runner.invoke(
        nxpimage.main,
        ["iped", "parse", "-f", "mimx943", "-b", table_path, "-o", parsed_config_path],
    )

    parsed_config = Config.create_from_file(parsed_config_path)
    parsed_iped = Iped.load_from_config(parsed_config)
    assert isinstance(parsed_iped, IpedV1)
    assert parsed_iped.export() == load_binary(table_path)


def test_nxpimage_iped_template(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test IPED get-template CLI command."""
    template = os.path.join(tmpdir, "iped_template.yaml")

    cli_runner.invoke(nxpimage.main, ["iped", "get-template", "-f", "mimx943", "-o", template])

    assert os.path.isfile(template)


def test_nxpimage_bootable_image_iped_keyblob(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test bootable-image keyblob segment can be built from IPED V1 YAML."""
    iped_config = os.path.join(tmpdir, "iped.yaml")
    _write_iped_v1_config(iped_config, os.path.join(tmpdir, "iped_out"))
    bootable_config = {
        "family": "mimx943",
        "memory_type": "flexspi_nor",
        "output": os.path.join(tmpdir, "bootable.bin"),
        "keyblob": iped_config,
    }
    bootable_config_path = os.path.join(tmpdir, "bootable.yaml")
    write_file(yaml.safe_dump(bootable_config), bootable_config_path)

    cli_runner.invoke(
        nxpimage.main, ["bootable-image", "export", "-c", bootable_config_path], expected_code=0
    )

    output = load_binary(bootable_config["output"])
    assert len(output) == 0x400
    # V1 header tag in LE word at byte 3
    assert output[3] == 0x4C


def test_nxpimage_bootable_image_raw_binary_keyblob(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test IPED-enabled families still accept raw binary keyblob files."""
    keyblob_path = os.path.join(tmpdir, "keyblob.bin")
    keyblob_data = bytes(range(256))
    write_file(keyblob_data, keyblob_path, mode="wb")
    bootable_config = {
        "family": "mimx943",
        "memory_type": "flexspi_nor",
        "output": os.path.join(tmpdir, "bootable.bin"),
        "keyblob": keyblob_path,
    }
    bootable_config_path = os.path.join(tmpdir, "bootable.yaml")
    write_file(yaml.safe_dump(bootable_config), bootable_config_path)

    cli_runner.invoke(
        nxpimage.main, ["bootable-image", "export", "-c", bootable_config_path], expected_code=0
    )

    assert load_binary(bootable_config["output"]) == keyblob_data
