#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test FCB part of nxpimage app."""
import filecmp
import os

import pytest
import yaml

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.xmcd.xmcd import XMCD, MemoryType
from spsdk.utils.misc import (
    Endianness,
    load_binary,
    load_configuration,
    load_file,
    use_working_directory,
    write_file,
)
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family,mem_type,config_type,option",
    [
        ("mimxrt1176", "semc_sdram", "simplified", None),
        ("mimxrt1176", "semc_sdram", "full", None),
        ("mimxrt1176", "flexspi_ram", "simplified", 0),
        ("mimxrt1176", "flexspi_ram", "simplified", 1),
        ("mimxrt1176", "flexspi_ram", "full", None),
        ("mimxrt1166", "semc_sdram", "simplified", None),
        ("mimxrt1166", "semc_sdram", "full", None),
        ("mimxrt1166", "flexspi_ram", "simplified", 0),
        ("mimxrt1166", "flexspi_ram", "simplified", 1),
        ("mimxrt1166", "flexspi_ram", "full", None),
        ("mimxrt798s", "xspi_ram", "simplified", None),
    ],
)
def test_nxpimage_xmcd_export(
    cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, config_type, option
):
    with use_working_directory(data_dir):
        file_base_name = f"{mem_type}_{config_type}"
        if option is not None:
            file_base_name += f"_{option}"
        config_file_path = os.path.join(data_dir, "xmcd", family, f"{file_base_name}.yaml")
        out_file = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}_exported.bin")
        cmd = ["bootable-image", "xmcd", "export", "-c", config_file_path, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "xmcd", family, f"{file_base_name}.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,config_type,option",
    [
        ("mimxrt1176", "semc_sdram", "simplified", None),
        ("mimxrt1176", "semc_sdram", "full", None),
        ("mimxrt1176", "flexspi_ram", "simplified", 0),
        ("mimxrt1176", "flexspi_ram", "simplified", 1),
        ("mimxrt1176", "flexspi_ram", "full", None),
        ("mimxrt1166", "semc_sdram", "simplified", None),
        ("mimxrt1166", "semc_sdram", "full", None),
        ("mimxrt1166", "flexspi_ram", "simplified", 0),
        ("mimxrt1166", "flexspi_ram", "simplified", 1),
        ("mimxrt1166", "flexspi_ram", "full", None),
        ("mimxrt798s", "xspi_ram", "simplified", None),
    ],
)
def test_nxpimage_xmcd_parse_cli(
    cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, config_type, option
):
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "xmcd", family)
        output_file = os.path.join(tmpdir, f"xmcd_{family}_{mem_type}_{config_type}.yaml")
        file_base_name = f"{mem_type}_{config_type}"
        if option is not None:
            file_base_name += f"_{option}"
        bin_path = os.path.join(data_folder, f"{file_base_name}.bin")

        cmd = [
            "bootable-image",
            "xmcd",
            "parse",
            "-f",
            family,
            "-b",
            bin_path,
            "-o",
            output_file,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(output_file)


@pytest.mark.parametrize(
    "family",
    ["mimxrt1176", "mimxrt1166", "mimxrt1189", "mimxrt798s"],
)
def test_nxpimage_xmcd_template_cli(cli_runner: CliRunner, tmpdir, data_dir, family):
    templates_folder = os.path.join(data_dir, "xmcd", family, "templates")
    cmd = f"bootable-image xmcd get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    mem_types = XMCD.get_supported_memory_types(family)
    for mem_type in mem_types:
        config_types = XMCD.get_supported_configuration_types(family, mem_type)
        for config_type in config_types:
            template_name = f"xmcd_{family}_{mem_type.label}_{config_type.label}.yaml"
            new_template_path = os.path.join(tmpdir, template_name)
            assert os.path.isfile(new_template_path)
            with open(new_template_path) as f:
                new_template = yaml.safe_load(f)
            ref_template_path = os.path.join(templates_folder, template_name)
            with open(ref_template_path) as f:
                ref_template = yaml.safe_load(f)
            assert new_template == ref_template


@pytest.mark.parametrize(
    "mem_type,config_type,option",
    [
        ("semc_sdram", "simplified", None),
        ("semc_sdram", "full", None),
        ("flexspi_ram", "simplified", 0),
        ("flexspi_ram", "simplified", 1),
        ("flexspi_ram", "full", None),
    ],
)
def test_nxpimage_xmcd_export_invalid(data_dir, mem_type, config_type, option):
    file_base_name = f"{mem_type}_{config_type}"
    if option is not None:
        file_base_name += f"_{option}"
    config = os.path.join(data_dir, "xmcd", "mimxrt1166", f"{file_base_name}.yaml")
    mandatory_fields = ["family", "mem_type", "config_type", "xmcd_settings"]
    # Check mandatory fields
    for mandatory_field in mandatory_fields:
        config_data = load_configuration(config)
        config_data.pop(mandatory_field)
        with pytest.raises(SPSDKError):
            XMCD.load_from_config(config_data)
    # Check invalid mem_type
    config_data = load_configuration(config)
    config_data["mem_type"] = "unknown"
    with pytest.raises(SPSDKError):
        XMCD.load_from_config(config_data)
    # Check invalid config_type
    config_data = load_configuration(config)
    config_data["config_type"] = "unknown"
    with pytest.raises(SPSDKError):
        XMCD.load_from_config(config_data)
    # Check unsupported family
    config_data = load_configuration(config)
    config_data["family"] = "rt5xx"
    with pytest.raises(SPSDKError):
        XMCD.load_from_config(config_data)


def test_nxpimage_supported_mem_types():
    mem_types = XMCD.get_supported_memory_types()
    assert len(mem_types) == 3
    mem_types[0] == MemoryType.FLEXSPI_RAM
    mem_types[0] == MemoryType.SEMC_SDRAM
    mem_types[0] == MemoryType.XSPI_RAM


def test_nxpimage_xmcd_validate(caplog, cli_runner: CliRunner, tmpdir, data_dir):
    family = "mimxrt1166"
    caplog.set_level(100_000)
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "xmcd", family, "semc_sdram_simplified.yaml")
        # Test Valid
        config = load_configuration(config_file)
        xmcd = XMCD.load_from_config(config)
        bin_path = os.path.join(tmpdir, f"xmcd.bin")
        write_file(xmcd.export(), bin_path, mode="wb")

        cmd = [
            "bootable-image",
            "xmcd",
            "verify",
            "-f",
            family,
            "-b",
            bin_path,
        ]
        result = cli_runner.invoke(nxpimage.main, cmd)
        assert "XMCD(Succeeded)" in result.output
        # Test Invalid
        config = load_configuration(config_file)
        config["xmcd_settings"]["header"]["bitfields"]["tag"] = 14
        xmcd = XMCD.load_from_config(config)
        write_file(xmcd.export(), bin_path, mode="wb")
        result = cli_runner.invoke(nxpimage.main, cmd)
        assert "XMCD(Error)" in result.output
        assert "Tag(Error): Does not match the tag 12" in result.output


@pytest.mark.parametrize(
    "mem_type,config_type,expected_crc",
    [
        ("semc_sdram", "simplified", "bc333806"),
        ("semc_sdram", "full", "762a8d08"),
        ("flexspi_ram", "full", "fb45c9eb"),
        ("flexspi_ram", "simplified_0", "ee57b489"),
        ("flexspi_ram", "simplified_1", "20fa163a"),
    ],
)
def test_nxpimage_xmcd_crc(data_dir, mem_type, config_type, expected_crc):
    family = "mimxrt1176"
    data_folder = os.path.join(data_dir, "xmcd", family)
    bin_path = os.path.join(data_folder, f"{mem_type}_{config_type}.bin")
    xmcd = XMCD.parse(load_binary(bin_path), family=family)
    assert xmcd.crc == bytes.fromhex(expected_crc)


@pytest.mark.parametrize(
    "family,crc_sum_fuse_id",
    [("mimxrt1166", 73), ("mimxrt1176", 73), ("mimxrt1189", 32)],
)
def test_nxpimage_xmcd_crc_fuses_script(
    cli_runner: CliRunner, tmpdir, data_dir, family: str, crc_sum_fuse_id
):
    # we take any XMCD binary as there are no differences between families
    binary_path = os.path.join(data_dir, "xmcd", "mimxrt1176", "semc_sdram_simplified.bin")
    fuses_script = os.path.join(tmpdir, "fuses.txt")
    cmd = [
        "bootable-image",
        "xmcd",
        "crc-fuses-script",
        "-b",
        binary_path,
        "-f",
        family,
        "-o",
        fuses_script,
    ]
    result = cli_runner.invoke(nxpimage.main, cmd)
    assert "Created fuses script" in result.output
    content = load_file(fuses_script, mode="r")
    assert "blhost XMCD CRC fuses programming script" in content
    assert f"Family: {family} Revision: latest" in content
    assert f"WARNING! Partially set register, check all bitfields before writing" in content
    assert f"efuse-program-once {crc_sum_fuse_id} 0xBC333806" in content
