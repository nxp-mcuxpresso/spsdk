#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for IPED table commands in nxpimage application."""

import os
from typing import Any

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.image.iped.iped import Iped, IpedV1, IpedV2
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, write_file
from tests.cli_runner import CliRunner

RT266X_FLASH_BASE = 0x60000000
RT266X_CONTEXT_START = RT266X_FLASH_BASE + 0x1000
RT266X_CONTEXT_END = RT266X_FLASH_BASE + 0x2000


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


def _write_iped_v2_config(
    path: str,
    output_folder: str,
    family: str = "mimxrt2662",
    data_blob: str | None = None,
) -> None:
    """Write a minimal IPED V2 configuration file.

    :param path: Output configuration path.
    :param output_folder: IPED output folder.
    :param family: Target family.
    :param data_blob: Optional path to plain data blob for encryption.
    """
    config = {
        "family": family,
        "output_folder": output_folder,
        "output_name": "iped_table",
        "output_format": "bin",
        "keyblob_address": hex(RT266X_FLASH_BASE),
        "device": "rt2660_a0",
        "instance": "xspi0",
        "fw_version": "0x44332211",
        "contexts": [
            {
                "start_address": hex(RT266X_CONTEXT_START),
                "end_address": hex(RT266X_CONTEXT_END),
                "mode": "ctr",
                "nonce": "0x0011223344556677",
                "iv": "0x0011223344556677",
                "aad": "0x0000000000000000",
                "key": "0x000102030405060708090a0b0c0d0e0f",
            }
        ],
    }
    if data_blob:
        config["data_blobs"] = [{"data": data_blob, "address": hex(RT266X_CONTEXT_START)}]
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


def test_nxpimage_iped_verify(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test IPED verify CLI command with V1 format for mimx943."""
    config_path = os.path.join(tmpdir, "iped.yaml")
    output_folder = os.path.join(tmpdir, "out")
    _write_iped_v1_config(config_path, output_folder)
    cli_runner.invoke(nxpimage.main, ["iped", "export", "-c", config_path])
    table_path = os.path.join(output_folder, "iped_config.bin")

    result = cli_runner.invoke(nxpimage.main, ["iped", "verify", "-f", "mimx943", "-b", table_path])
    assert "Succeeded" in result.output
    assert "Overall  result: Succeeded" in result.output


def test_nxpimage_iped_template_rt266x_addresses(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test RT266x template exposes RT266x defaults and derivation-related fields."""
    template = os.path.join(tmpdir, "iped_template_rt266x.yaml")

    cli_runner.invoke(nxpimage.main, ["iped", "get-template", "-f", "mimxrt2662", "-o", template])

    with open(template, "r", encoding="utf-8") as template_file:
        content = template_file.read()
    assert "output_folder: iped_output" in content
    assert "keyblob_address: '0x60000000'" in content
    assert "address: '0x60001000'" in content
    assert "address: '0x28001000'" not in content
    assert "instance: xspi0" in content
    assert "fw_version: '0x44332211'" in content
    assert "lifecycle: oem_open" in content
    assert "oem_clsd" in content
    assert "oem_lckd" in content
    assert "oem_closed" not in content
    assert "oem_locked" not in content
    assert "double_encryption: false" in content
    assert "contexts:" in content
    assert "region_id:" in content
    assert "nonce:" in content
    assert "image_name: iped_image" in content
    assert "cust_mk_sk:" in content
    assert "srkh:" in content
    assert "pqc_srkh:" in content
    assert "regions:" not in content
    assert "config_output:" not in content


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


def test_nxpimage_iped_export_v2_rt266x(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test IPED export CLI command with V2 config for RT266x family."""
    family = FamilyRevision("mimxrt2662")
    if family not in Iped.get_supported_families():
        pytest.skip("mimxrt2662 is not available in current database setup.")

    config_path = os.path.join(tmpdir, "iped_v2.yaml")
    output_folder = os.path.join(tmpdir, "out")
    _write_iped_v2_config(config_path, output_folder, family=family.name)

    cli_runner.invoke(nxpimage.main, ["iped", "export", "-c", config_path], expected_code=0)

    output_file = os.path.join(output_folder, "iped_table.bin")
    assert os.path.isfile(output_file)
    parsed = Iped.parse(load_binary(output_file), family=family)
    assert isinstance(parsed, IpedV2)


def test_nxpimage_iped_export_v2_rt266x_encryption(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test RT266x V2 export also generates encrypted artifacts from data_blobs."""
    family = FamilyRevision("mimxrt2662")
    if family not in Iped.get_supported_families():
        pytest.skip("mimxrt2662 is not available in current database setup.")
    plain_path = os.path.join(tmpdir, "plain.bin")
    plain_data = b"\x10\x20\x30\x40\x50\x60"
    write_file(plain_data, plain_path, mode="wb")

    config_path = os.path.join(tmpdir, "iped_v2_encrypt.yaml")
    output_folder = os.path.join(tmpdir, "out_encrypt")
    _write_iped_v2_config(
        config_path,
        output_folder,
        family=family.name,
        data_blob=plain_path,
    )

    cli_runner.invoke(nxpimage.main, ["iped", "export", "-c", config_path], expected_code=0)

    table_file = os.path.join(output_folder, "iped_table.bin")
    encrypted_file = os.path.join(output_folder, "encrypted_blob.bin")
    image_file = os.path.join(output_folder, "iped_image.bin")
    assert os.path.isfile(table_file)
    assert os.path.isfile(encrypted_file)
    assert os.path.isfile(image_file)

    table = load_binary(table_file)
    encrypted = load_binary(encrypted_file)
    full_image = load_binary(image_file)
    assert isinstance(Iped.parse(table, family=family), IpedV2)
    assert encrypted != plain_data
    assert len(encrypted) % 8 == 0
    assert full_image[: len(table)] == table
    encrypted_offset = RT266X_CONTEXT_START - RT266X_FLASH_BASE
    assert full_image[encrypted_offset : encrypted_offset + len(encrypted)] == encrypted


def test_nxpimage_bootable_image_iped_keyblob_v2_rt266x(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test RT266x bootable-image keyblob accepts V2 IPED config and exports artifacts."""
    family = FamilyRevision("mimxrt2662")
    if family not in Iped.get_supported_families():
        pytest.skip("mimxrt2662 is not available in current database setup.")
    plain_path = os.path.join(tmpdir, "plain_bimg.bin")
    write_file(b"\xaa\xbb\xcc\xdd", plain_path, mode="wb")

    iped_config = os.path.join(tmpdir, "iped_v2_bootable.yaml")
    _write_iped_v2_config(
        iped_config,
        os.path.join(tmpdir, "iped_out"),
        family=family.name,
        data_blob=plain_path,
    )
    post_export_dir = os.path.join(tmpdir, "post_export")
    bootable_config = {
        "family": family.name,
        "memory_type": "xspi_nor",
        "output": os.path.join(tmpdir, "bootable_rt266x.bin"),
        "keyblob": iped_config,
        "post_export": post_export_dir,
    }
    bootable_config_path = os.path.join(tmpdir, "bootable_rt266x.yaml")
    write_file(yaml.safe_dump(bootable_config), bootable_config_path)

    cli_runner.invoke(
        nxpimage.main, ["bootable-image", "export", "-c", bootable_config_path], expected_code=0
    )

    output = load_binary(bootable_config["output"])
    assert isinstance(Iped.parse(output[:0x400], family=family), IpedV2)
    assert os.path.isfile(os.path.join(post_export_dir, "iped_table.bin"))
    assert os.path.isfile(os.path.join(post_export_dir, "encrypted_blob.bin"))
    assert os.path.isfile(os.path.join(post_export_dir, "iped_image.bin"))
