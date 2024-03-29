#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Bootable Image part of nxpimage app."""
import filecmp
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "mem_type,family,config",
    [
        ("flexspi_nor", "rt5xx", "config.yaml"),
        ("flexspi_nor", "rt6xx", "config.yaml"),
        ("flexspi_nor", "lpc55s3x", "config.yaml"),
        ("flexspi_nor", "lpc55s3x", "config_yaml.yaml"),
        ("internal", "lpc55s3x", "config.yaml"),
        ("internal", "lpc55s3x", "config_yaml.yaml"),
        ("flexspi_nor", "rt101x", "config.yaml"),
        ("flexspi_nor", "rt102x", "config.yaml"),
        ("flexspi_nor", "rt104x", "config.yaml"),
        ("flexspi_nor", "rt105x", "config.yaml"),
        ("flexspi_nor", "rt106x", "config.yaml"),
        ("flexspi_nor", "rt116x", "config.yaml"),
        ("flexspi_nor", "rt117x", "config.yaml"),
        ("flexspi_nor", "rt118x", "config.yaml"),
        ("flexspi_nor", "rt118x", "config_yaml.yaml"),
        ("flexspi_nor_xmcd", "rt118x", "config.yaml"),
        ("flexspi_nor_xmcd", "rt118x", "config_yaml.yaml"),
        ("semc_nand", "rt116x", "config.yaml"),
        ("semc_nand", "rt117x", "config.yaml"),
        ("flexspi_nand", "rt116x", "config.yaml"),
        ("flexspi_nand", "rt117x", "config.yaml"),
        ("flexspi_nand", "rt117x", "config_yaml.yaml"),
    ],
)
def test_nxpimage_bimg_merge(cli_runner: CliRunner, tmpdir, data_dir, mem_type, family, config):
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "bootable_image", family, mem_type, config)
        out_file = os.path.join(tmpdir, f"bimg_{family}_merged.bin")
        cmd = ["bootable-image", "merge", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "bootable_image", family, mem_type, "merged_image.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,config_dir,blocks",
    [
        ("rt5xx", "flexspi_nor", "flexspi_nor", ["fcb", "keyblob", "keystore", "mbi"]),
        ("rt6xx", "flexspi_nor", "flexspi_nor", ["fcb", "keyblob", "keystore", "mbi"]),
        ("lpc55s3x", "flexspi_nor", "flexspi_nor", ["fcb", "mbi"]),
        ("lpc55s3x", "internal", "internal", ["mbi"]),
        ("rt101x", "flexspi_nor", "flexspi_nor", ["fcb", "keyblob", "hab_container"]),
        (
            "rt102x",
            "flexspi_nor",
            "flexspi_nor",
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        (
            "rt104x",
            "flexspi_nor",
            "flexspi_nor",
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        (
            "rt105x",
            "flexspi_nor",
            "flexspi_nor",
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        (
            "rt106x",
            "flexspi_nor",
            "flexspi_nor",
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        ("rt116x", "flexspi_nor", "flexspi_nor", ["keyblob", "fcb", "keystore", "hab_container"]),
        ("rt117x", "flexspi_nor", "flexspi_nor", ["keyblob", "fcb", "keystore", "hab_container"]),
        (
            "rt117x",
            "flexspi_nor",
            "flexspi_nor_0xff_pattern",
            ["fcb", "hab_container"],
        ),
        ("rt117x", "semc_nand", "semc_nand", ["hab_container"]),
        ("rt117x", "flexspi_nand", "flexspi_nand", ["hab_container"]),
        ("rt118x", "flexspi_nor", "flexspi_nor", ["fcb", "ahab_container"]),
        ("rt118x", "flexspi_nor", "flexspi_nor_xmcd", ["fcb", "ahab_container", "xmcd"]),
        ("rt116x", "semc_nand", "semc_nand", ["hab_container"]),
        ("rt116x", "flexspi_nand", "flexspi_nand", ["hab_container"]),
    ],
)
def test_nxpimage_bimg_parse_cli(
    cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, config_dir, blocks
):
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "bootable_image", family, config_dir)
        input_binary = os.path.join(data_folder, "merged_image.bin")
        cmd = [
            "bootable-image",
            "parse",
            "-m",
            mem_type,
            "-f",
            family,
            "-b",
            input_binary,
            "-o",
            str(tmpdir),
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        bimg_config = os.path.join(tmpdir, f"bootable_image_{family}_{mem_type}.yaml")
        assert os.path.isfile(bimg_config)
        generated = load_configuration(bimg_config)
        reference = load_configuration(
            os.path.join(data_dir, "bootable_image", family, mem_type, "config.yaml")
        )
        assert sorted(generated.keys()) == sorted(reference.keys())

        for block in blocks:
            assert filecmp.cmp(
                os.path.join(tmpdir, f"segment_{block}.bin"),
                os.path.join(data_folder, f"{block}.bin"),
                shallow=False,
            )
        if "fcb" in blocks:
            assert os.path.isfile(os.path.join(tmpdir, "segment_fcb.yaml"))


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("rt5xx", ["flexspi_nor"]),
        ("rt6xx", ["flexspi_nor"]),
        ("lpc55s3x", ["flexspi_nor", "internal"]),
        ("rt101x", ["flexspi_nor"]),
        ("rt102x", ["flexspi_nor"]),
        ("rt104x", ["flexspi_nor"]),
        ("rt105x", ["flexspi_nor"]),
        ("rt106x", ["flexspi_nor"]),
        ("rt116x", ["flexspi_nor", "semc_nand", "flexspi_nand"]),
        ("rt117x", ["flexspi_nor", "semc_nand", "flexspi_nand"]),
        ("rt118x", ["flexspi_nor"]),
    ],
)
def test_nxpimage_bimg_template_cli(cli_runner: CliRunner, tmpdir, data_dir, family, mem_types):
    cmd = f"bootable-image get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"bootimg_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)
        generated = load_configuration(template_name)
        reference = load_configuration(
            os.path.join(data_dir, "bootable_image", family, mem_type, "config.yaml")
        )
        assert sorted(generated.keys()) == sorted(reference.keys())


@pytest.mark.parametrize(
    "family,input_path,expected_mem_type",
    [
        ("rt5xx", "rt5xx/flexspi_nor/merged_image.bin", "flexspi_nor"),
        ("lpc55s3x", "lpc55s3x/internal/merged_image.bin", "internal"),
        ("lpc55s3x", "rt5xx/flexspi_nor/merged_image.bin", None),
        ("rt102x", "rt5xx/flexspi_nor/merged_image.bin", None),
        ("rt118x", "rt5xx/flexspi_nor/merged_image.bin", None),
        ("rt116x", "rt116x/flexspi_nor/merged_image.bin", "flexspi_nor"),
        ("rt116x", "rt116x/flexspi_nand/merged_image.bin", "flexspi_nand"),
        ("rt116x", "rt116x/semc_nand/merged_image.bin", "flexspi_nand"),
    ],
)
def test_nxpimage_bimg_parse_autodetect_mem_type(data_dir, family, input_path, expected_mem_type):
    input_binary_path = os.path.join(data_dir, "bootable_image", input_path)
    input_binary = load_binary(input_binary_path)
    if expected_mem_type:
        bimg = BootableImage.parse(input_binary, family)
        assert bimg.mem_type == expected_mem_type
    else:
        with pytest.raises(SPSDKError):
            BootableImage.parse(input_binary, family)
