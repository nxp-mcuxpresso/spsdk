#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Bootable Image part of nxpimage app."""
import filecmp
import logging
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import BootableImageSegment
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "mem_type,family,configuration,config_file",
    [
        ("flexspi_nor", "rt5xx", "xip_crc", "config.yaml"),
        ("flexspi_nor", "rt5xx", "xip_plain", "config.yaml"),
        ("flexspi_nor", "rt6xx", "xip", "config.yaml"),
        ("flexspi_nor", "rt6xx", "load_to_ram", "config.yaml"),
        ("flexspi_nor", "lpc55s3x", None, "config.yaml"),
        ("flexspi_nor", "lpc55s3x", None, "config_yaml.yaml"),
        ("internal", "lpc55s3x", None, "config.yaml"),
        ("internal", "lpc55s3x", None, "config_yaml.yaml"),
        ("flexspi_nor", "rt1010", None, "config.yaml"),
        ("flexspi_nor", "rt1015", None, "config.yaml"),
        ("flexspi_nor", "rt102x", None, "config.yaml"),
        ("flexspi_nor", "rt104x", None, "config.yaml"),
        ("flexspi_nor", "rt105x", "fcb_bee_hab", "config.yaml"),
        ("flexspi_nor", "rt106x", None, "config.yaml"),
        ("flexspi_nor", "rt116x", None, "config.yaml"),
        ("flexspi_nor", "rt117x", "0x00_pattern", "config.yaml"),
        ("flexspi_nor", "rt118x", "no_xmcd", "config.yaml"),
        ("flexspi_nor", "rt118x", "no_xmcd", "config_yaml.yaml"),
        ("flexspi_nor", "rt118x", "with_xmcd", "config.yaml"),
        ("flexspi_nor", "rt118x", "with_xmcd", "config_yaml.yaml"),
        ("semc_nand", "rt116x", None, "config.yaml"),
        ("semc_nand", "rt117x", None, "config.yaml"),
        ("flexspi_nand", "rt116x", None, "config.yaml"),
        ("flexspi_nand", "rt117x", None, "config.yaml"),
        ("flexspi_nand", "rt117x", None, "config_yaml.yaml"),
    ],
)
def test_nxpimage_bimg_merge(
    cli_runner: CliRunner, tmpdir, data_dir, mem_type, family, configuration, config_file
):
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", family, mem_type)
        if configuration:
            config_dir = os.path.join(config_dir, configuration)
        config_file_path = os.path.join(config_dir, config_file)
        out_file = os.path.join(tmpdir, f"bimg_{family}_merged.bin")
        cmd = ["bootable-image", "merge", "-c", config_file_path, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(config_dir, "merged_image.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type,configuration,blocks",
    [
        ("rt5xx", "flexspi_nor", "xip_crc", ["fcb", "keyblob", "keystore", "mbi"]),
        ("rt5xx", "flexspi_nor", "xip_plain", ["fcb", "mbi"]),
        ("rt6xx", "flexspi_nor", "xip", ["fcb", "keyblob", "keystore", "mbi"]),
        ("rt6xx", "flexspi_nor", "load_to_ram", ["mbi"]),
        ("lpc55s3x", "flexspi_nor", None, ["fcb", "mbi"]),
        ("lpc55s3x", "internal", None, ["mbi"]),
        ("rt1010", "flexspi_nor", None, ["fcb", "keyblob", "hab_container"]),
        ("rt1015", "flexspi_nor", None, ["fcb", "hab_container"]),
        (
            "rt102x",
            "flexspi_nor",
            None,
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        (
            "rt104x",
            "flexspi_nor",
            None,
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        (
            "rt105x",
            "flexspi_nor",
            "fcb_bee_hab",
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        (
            "rt105x",
            "flexspi_nor",
            "fcb_hab",
            ["fcb", "hab_container"],
        ),
        (
            "rt106x",
            "flexspi_nor",
            None,
            ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
        ),
        ("rt116x", "flexspi_nor", None, ["keyblob", "fcb", "keystore", "hab_container"]),
        ("rt117x", "flexspi_nor", "0x00_pattern", ["keyblob", "fcb", "keystore", "hab_container"]),
        (
            "rt117x",
            "flexspi_nor",
            "0xff_pattern",
            ["fcb", "hab_container"],
        ),
        ("rt117x", "semc_nand", None, ["hab_container"]),
        ("rt117x", "flexspi_nand", None, ["hab_container"]),
        ("rt118x", "flexspi_nor", "no_xmcd", ["fcb", "ahab_container"]),
        ("rt118x", "flexspi_nor", "with_xmcd", ["fcb", "ahab_container", "xmcd"]),
        ("rt118x", "flexspi_nor", "ahab_only", ["ahab_container"]),
        ("rt116x", "semc_nand", None, ["hab_container"]),
        ("rt116x", "flexspi_nand", None, ["hab_container"]),
        ("mcxn9xx", "flexspi_nor", "full", ["fcb", "mbi"]),
        ("rw61x", "flexspi_nor", None, ["fcb", "mbi"]),
    ],
)
def test_nxpimage_bimg_parse_cli(
    cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, configuration, blocks
):
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", family, mem_type)
        if configuration:
            config_dir = os.path.join(config_dir, configuration)
        input_binary = os.path.join(config_dir, "merged_image.bin")
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
        reference = load_configuration(os.path.join(config_dir, "config.yaml"))
        assert sorted(generated.keys()) == sorted(reference.keys())
        if "image_version" in reference:
            assert reference["image_version"] == generated["image_version"]

        for block in blocks:
            assert filecmp.cmp(
                os.path.join(tmpdir, f"segment_{block}.bin"),
                os.path.join(config_dir, f"{block}.bin"),
                shallow=False,
            )
        if "fcb" in blocks:
            assert os.path.isfile(os.path.join(tmpdir, "segment_fcb.yaml"))


@pytest.mark.parametrize(
    "family,configs",
    [
        ("rt5xx", [("flexspi_nor", "xip_crc")]),
        ("rt6xx", [("flexspi_nor", "xip")]),
        ("lpc55s3x", ["flexspi_nor", "internal"]),
        ("rt1010", ["flexspi_nor"]),
        ("rt1015", ["flexspi_nor"]),
        ("rt102x", ["flexspi_nor"]),
        ("rt104x", ["flexspi_nor"]),
        ("rt105x", [("flexspi_nor", "fcb_bee_hab")]),
        ("rt106x", ["flexspi_nor"]),
        ("rt116x", ["flexspi_nor", "semc_nand", "flexspi_nand"]),
        ("rt117x", [("flexspi_nor", "0x00_pattern"), "semc_nand", "flexspi_nand"]),
        ("rt118x", [("flexspi_nor", "no_xmcd")]),
        ("mcxn9xx", [("flexspi_nor", "full")]),
    ],
)
def test_nxpimage_bimg_template_cli(cli_runner: CliRunner, tmpdir, data_dir, family, configs):
    cmd = f"bootable-image get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    for config in configs:
        mem_type = config[0] if isinstance(config, tuple) else config
        config_dir = config[1] if isinstance(config, tuple) else None
        template_name = os.path.join(tmpdir, f"bootimg_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)
        generated = load_configuration(template_name)
        reference_dir = os.path.join(data_dir, "bootable_image", family, mem_type)
        if config_dir:
            reference_dir = os.path.join(reference_dir, config_dir)
        reference = load_configuration(os.path.join(reference_dir, "config.yaml"))
        assert sorted(generated.keys()) == sorted(reference.keys())


@pytest.mark.parametrize(
    "family,input_path,expected_mem_type",
    [
        ("rt5xx", "rt5xx/flexspi_nor/xip_crc/merged_image.bin", "flexspi_nor"),
        ("lpc55s3x", "lpc55s3x/internal/merged_image.bin", "internal"),
        ("lpc55s3x", "rt5xx/flexspi_nor/xip_crc/merged_image.bin", None),
        ("rt102x", "rt5xx/flexspi_nor/xip_crc/merged_image.bin", None),
        ("rt118x", "rt5xx/flexspi_nor/xip_crc/merged_image.bin", None),
        ("rt116x", "rt116x/flexspi_nor/merged_image.bin", "flexspi_nor"),
        ("rt116x", "rt116x/flexspi_nand/merged_image.bin", "flexspi_nand"),
        ("rt116x", "rt116x/semc_nand/merged_image.bin", "flexspi_nand"),
        ("mcxn9xx", "mcxn9xx/flexspi_nor/full/merged_image.bin", "flexspi_nor"),
    ],
)
def test_nxpimage_bimg_parse_autodetect_mem_type(data_dir, family, input_path, expected_mem_type):
    input_binary_path = os.path.join(data_dir, "bootable_image", input_path)
    input_binary = load_binary(input_binary_path)
    if expected_mem_type:
        bimg = BootableImage.parse(input_binary, family)
        assert bimg.init_offset == 0
        assert bimg.mem_type == expected_mem_type
    else:
        with pytest.raises(SPSDKError):
            BootableImage.parse(input_binary, family)


@pytest.mark.parametrize(
    "family,mem_type,configuration,blocks",
    [
        ("mcxn9xx", "flexspi_nor", "full", ["fcb", "mbi"]),
        ("mcxn9xx", "flexspi_nor", "starting_fcb", ["fcb", "mbi"]),
        ("mcxn9xx", "flexspi_nor", "starting_mbi", ["mbi"]),
    ],
)
def test_nxpimage_bimg_parse_incomplete_cli(
    cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, configuration, blocks
):
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", family, mem_type, configuration)
        input_binary = os.path.join(config_dir, "merged_image.bin")
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
        reference = load_configuration(os.path.join(config_dir, "config.yaml"))
        assert sorted(generated.keys()) == sorted(reference.keys())
        assert generated["init_offset"] == reference["init_offset"]

        for block in blocks:
            assert filecmp.cmp(
                os.path.join(tmpdir, f"segment_{block}.bin"),
                os.path.join(config_dir, f"{block}.bin"),
                shallow=False,
            )


def test_find_the_exact_layout_match_first(caplog, data_dir):
    caplog.set_level(logging.WARNING)
    bimg_bin = os.path.join(data_dir, "bootable_image", "lpc55s3x", "internal", "merged_image.bin")
    bimg = BootableImage.parse(load_binary(bimg_bin), "lpc55s3x")
    assert bimg.mem_type == "internal"
    # One warning regarding multiple mem types is shown
    # spi_recovery_mbi and internal should fit
    assert len(caplog.messages) == 1


def test_get_segment(data_dir):
    bimg_bin = os.path.join(
        data_dir, "bootable_image", "rt5xx", "flexspi_nor", "xip_plain", "merged_image.bin"
    )
    bimg = BootableImage.parse(load_binary(bimg_bin), "rt5xx")
    segments = {
        BootableImageSegment.FCB: 1024,
        BootableImageSegment.IMAGE_VERSION: 1536,
        BootableImageSegment.MBI: 4096,
    }
    for segment in segments:
        assert bimg.get_segment(segment).full_image_offset == segments[segment]


def test_image_info(data_dir):
    family = "rt5xx"
    bimg_bin = os.path.join(
        data_dir, "bootable_image", family, "flexspi_nor", "xip_plain", "merged_image.bin"
    )
    bimg = BootableImage.parse(load_binary(bimg_bin), family)
    info = bimg.image_info()
    assert info.name == f"Bootable Image for {family}"
    assert info.image_name == f"Bootable Image for {family}"
    assert info.offset == 0
    assert info.pattern.pattern == bimg.image_pattern
    sub_images = {"fcb": 1024, "image_version": 1536, "mbi": 4096}
    assert len(info.sub_images) == len(sub_images)
    for sub_image in info.sub_images:
        assert sub_image.offset == sub_images[sub_image.name]


@pytest.mark.parametrize(
    "family,mem_type,configuration,init_offset,segments_count",
    [
        ("mcxn9xx", "flexspi_nor", "full", 0x0, 3),
        ("mcxn9xx", "flexspi_nor", "starting_fcb", 0x400, 3),
        ("mcxn9xx", "flexspi_nor", "starting_mbi", 0x1000, 1),
    ],
)
def test_nxpimage_bimg_parse_image_adjustement(
    data_dir, family, mem_type, configuration, init_offset, segments_count
):
    input_binary_path = os.path.join(
        data_dir, "bootable_image", family, mem_type, configuration, "merged_image.bin"
    )
    input_binary = load_binary(input_binary_path)
    bimg = BootableImage.parse(input_binary, family, mem_type)
    assert bimg.init_offset == init_offset
    assert len(bimg.segments) == segments_count


def test_nxpimage_bimg_default_init_offset():
    for family in BootableImage.get_supported_families():
        for mem_type in BootableImage.get_supported_memory_types(family):
            BootableImage(family=family, mem_type=mem_type).init_offset == 0


@pytest.mark.parametrize(
    "family,mem_type,init_offset,actual_offset",
    [
        ("mcxn9xx", "flexspi_nor", 0x0, 0x0),
        ("mcxn9xx", "flexspi_nor", 0x3FF, 0x400),
        ("mcxn9xx", "flexspi_nor", 0x400, 0x400),
        ("mcxn9xx", "flexspi_nor", 0x401, 0x600),
        ("mcxn9xx", "flexspi_nor", 0x1000, 0x1000),
        ("mcxn9xx", "flexspi_nor", 0x1001, None),
        ("mcxn9xx", "flexspi_nor", -1, None),
        ("mcxn9xx", "flexspi_nor", BootableImageSegment.FCB, 0x400),
        ("mcxn9xx", "flexspi_nor", BootableImageSegment.IMAGE_VERSION_AP, 0x600),
        ("mcxn9xx", "flexspi_nor", BootableImageSegment.UNKNOWN, None),
    ],
)
def test_nxpimage_bimg_init_offset_setter(family, mem_type, init_offset, actual_offset):
    if actual_offset is not None:
        bimg = BootableImage(family=family, mem_type=mem_type, init_offset=init_offset)
        assert bimg.init_offset == actual_offset
        if isinstance(init_offset, int):
            bimg = BootableImage(family=family, mem_type=mem_type)
            bimg.init_offset = init_offset
            assert bimg.init_offset == actual_offset
    else:
        with pytest.raises(SPSDKError):
            BootableImage(family=family, mem_type=mem_type, init_offset=init_offset)
        if isinstance(init_offset, int):
            with pytest.raises(SPSDKError):
                bimg = BootableImage(family=family, mem_type=mem_type)
                bimg.init_offset = init_offset


def test_nxpimage_bimg_segments_index_is_updated(data_dir):
    config_dir = os.path.join(data_dir, "bootable_image", "mcxn9xx", "flexspi_nor", "starting_fcb")
    bimg = BootableImage.load_from_config(
        load_configuration(os.path.join(config_dir, "config.yaml")),
        search_paths=[config_dir],
    )
    segments = {
        BootableImageSegment.FCB: 0x0,
        BootableImageSegment.IMAGE_VERSION_AP: 0x200,
        BootableImageSegment.MBI: 0xC00,
    }
    assert len(bimg.segments) == len(segments)
    assert bimg.init_offset == 0x400
    for segment in bimg.segments:
        assert bimg.get_segment_offset(segment) == segments[segment.NAME]
    bimg.init_offset = 0x0
    segments = {
        BootableImageSegment.FCB: 0x400,
        BootableImageSegment.IMAGE_VERSION_AP: 0x600,
        BootableImageSegment.MBI: 0x1000,
    }
    assert len(bimg.segments) == len(segments)
    assert bimg.init_offset == 0x0
    for segment in bimg.segments:
        assert bimg.get_segment_offset(segment) == segments[segment.NAME]
    bimg.init_offset = 0x600
    segments = {
        BootableImageSegment.IMAGE_VERSION_AP: 0x0,
        BootableImageSegment.MBI: 0xA00,
    }
    assert len(bimg.segments) == len(segments)
    assert bimg.init_offset == 0x600
    for segment in bimg.segments:
        assert bimg.get_segment_offset(segment) == segments[segment.NAME]
    bimg.set_init_offset(BootableImageSegment.MBI)
    segments = {
        BootableImageSegment.MBI: 0x0,
    }
    assert len(bimg.segments) == len(segments)
    assert bimg.init_offset == 0x1000
    for segment in bimg.segments:
        assert bimg.get_segment_offset(segment) == segments[segment.NAME]


@pytest.mark.parametrize(
    "family,mem_type,configuration",
    [
        ("mcxn9xx", "flexspi_nor", "full"),
        ("mcxn9xx", "flexspi_nor", "starting_fcb"),
        ("mcxn9xx", "flexspi_nor", "starting_mbi"),
    ],
)
def test_nxpimage_bimg_parse_export(data_dir, family, mem_type, configuration):
    input_binary_path = os.path.join(
        data_dir, "bootable_image", family, mem_type, configuration, "merged_image.bin"
    )
    input_binary = load_binary(input_binary_path)
    bimg = BootableImage.parse(input_binary, family, mem_type)
    assert len(bimg.export()) == len(input_binary)
