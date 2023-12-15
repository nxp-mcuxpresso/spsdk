#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
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
from spsdk.utils.misc import load_configuration, use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family,mem_type,config_type,option",
    [
        ("rt117x", "semc_sdram", "simplified", None),
        ("rt117x", "semc_sdram", "full", None),
        ("rt117x", "flexspi_ram", "simplified", 0),
        ("rt117x", "flexspi_ram", "simplified", 1),
        ("rt117x", "flexspi_ram", "full", None),
        ("rt116x", "semc_sdram", "simplified", None),
        ("rt116x", "semc_sdram", "full", None),
        ("rt116x", "flexspi_ram", "simplified", 0),
        ("rt116x", "flexspi_ram", "simplified", 1),
        ("rt116x", "flexspi_ram", "full", None),
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
        ("rt117x", "semc_sdram", "simplified", None),
        ("rt117x", "semc_sdram", "full", None),
        ("rt117x", "flexspi_ram", "simplified", 0),
        ("rt117x", "flexspi_ram", "simplified", 1),
        ("rt117x", "flexspi_ram", "full", None),
        ("rt116x", "semc_sdram", "simplified", None),
        ("rt116x", "semc_sdram", "full", None),
        ("rt116x", "flexspi_ram", "simplified", 0),
        ("rt116x", "flexspi_ram", "simplified", 1),
        ("rt116x", "flexspi_ram", "full", None),
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
    ["rt117x", "rt116x", "rt118x"],
)
def test_nxpimage_xmcd_template_cli(cli_runner: CliRunner, tmpdir, data_dir, family):
    templates_folder = os.path.join(data_dir, "xmcd", family, "templates")
    cmd = f"bootable-image xmcd get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    mem_types = XMCD.get_supported_memory_types(family)
    for mem_type in mem_types:
        config_types = XMCD.get_supported_configuration_types(family, MemoryType.get(mem_type))
        for config_type in config_types:
            template_name = f"xmcd_{family}_{mem_type}_{config_type}.yaml"
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
    config = os.path.join(data_dir, "xmcd", "rt116x", f"{file_base_name}.yaml")
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
