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
from spsdk.image.mem_type import MemoryType
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from tests.cli_runner import CliRunner

FULL_LIST_TO_TEST = [
    ("mimxrt595s", "flexspi_nor", "xip_crc", ["fcb", "keyblob", "keystore", "mbi"]),
    ("mimxrt595s", "flexspi_nor", "xip_plain", ["fcb", "mbi"]),
    ("mimxrt685s", "flexspi_nor", "xip", ["fcb", "keyblob", "keystore", "mbi"]),
    ("mimxrt685s", "flexspi_nor", "load_to_ram", ["mbi"]),
    ("lpc55s36", "flexspi_nor", None, ["fcb", "mbi"]),
    ("lpc55s36", "internal", None, ["mbi"]),
    ("mimxrt1010", "flexspi_nor", None, ["fcb", "keyblob", "hab_container"]),
    ("mimxrt1015", "flexspi_nor", None, ["fcb", "hab_container"]),
    (
        "mimxrt1024",
        "flexspi_nor",
        None,
        ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
    ),
    (
        "mimxrt1040",
        "flexspi_nor",
        None,
        ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
    ),
    (
        "mimxrt1050",
        "flexspi_nor",
        "fcb_bee_hab",
        ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
    ),
    (
        "mimxrt1050",
        "flexspi_nor",
        "fcb_hab",
        ["fcb", "hab_container"],
    ),
    (
        "mimxrt1064",
        "flexspi_nor",
        None,
        ["fcb", "bee_header_0", "bee_header_1", "hab_container"],
    ),
    ("mimxrt1166", "flexspi_nor", None, ["keyblob", "fcb", "keystore", "hab_container"]),
    ("mimxrt1176", "flexspi_nor", "0x00_pattern", ["keyblob", "fcb", "keystore", "hab_container"]),
    (
        "mimxrt1176",
        "flexspi_nor",
        "0xff_pattern",
        ["fcb", "hab_container"],
    ),
    ("mimxrt1176", "semc_nand", None, ["hab_container"]),
    ("mimxrt1176", "flexspi_nand", None, ["hab_container"]),
    ("mimxrt1189", "flexspi_nor", "no_xmcd", ["fcb", "ahab_container"]),
    ("mimxrt1189", "flexspi_nor", "with_xmcd", ["fcb", "ahab_container", "xmcd"]),
    ("mimxrt1189", "flexspi_nor", "ahab_only", ["ahab_container"]),
    ("mimxrt1189", "flexspi_nor", "ahab_empty_hash", ["fcb", "ahab_container"]),
    ("mimxrt1166", "semc_nand", None, ["hab_container"]),
    ("mimxrt1166", "flexspi_nand", None, ["hab_container"]),
    ("mcxn947", "flexspi_nor", "full", ["fcb", "mbi"]),
    ("mcxn947", "flexspi_nor", "starting_fcb_1", ["fcb", "mbi"]),
    ("rw612", "flexspi_nor", None, ["fcb", "mbi"]),
]


@pytest.mark.parametrize(
    "mem_type,family,configuration,config_file",
    [
        ("flexspi_nor", "mimxrt595s", "xip_crc", "config.yaml"),
        ("flexspi_nor", "mimxrt595s", "xip_plain", "config.yaml"),
        ("flexspi_nor", "mimxrt685s", "xip", "config.yaml"),
        ("flexspi_nor", "mimxrt685s", "load_to_ram", "config.yaml"),
        ("flexspi_nor", "lpc55s36", None, "config.yaml"),
        ("flexspi_nor", "lpc55s36", None, "config_yaml.yaml"),
        ("internal", "lpc55s36", None, "config.yaml"),
        ("internal", "lpc55s36", None, "config_yaml.yaml"),
        ("flexspi_nor", "mimxrt1010", None, "config.yaml"),
        ("flexspi_nor", "mimxrt1015", None, "config.yaml"),
        ("flexspi_nor", "mimxrt1024", None, "config.yaml"),
        ("flexspi_nor", "mimxrt1040", None, "config.yaml"),
        ("flexspi_nor", "mimxrt1050", "fcb_bee_hab", "config.yaml"),
        ("flexspi_nor", "mimxrt1064", None, "config.yaml"),
        ("flexspi_nor", "mimxrt1166", None, "config.yaml"),
        ("flexspi_nor", "mimxrt1176", "0x00_pattern", "config.yaml"),
        ("flexspi_nor", "mimxrt1189", "no_xmcd", "config.yaml"),
        ("flexspi_nor", "mimxrt1189", "no_xmcd", "config_yaml.yaml"),
        ("flexspi_nor", "mimxrt1189", "with_xmcd", "config.yaml"),
        ("flexspi_nor", "mimxrt1189", "with_xmcd", "config_yaml.yaml"),
        ("semc_nand", "mimxrt1166", None, "config.yaml"),
        ("semc_nand", "mimxrt1176", None, "config.yaml"),
        ("flexspi_nand", "mimxrt1166", None, "config.yaml"),
        ("flexspi_nand", "mimxrt1176", None, "config.yaml"),
        ("flexspi_nand", "mimxrt1176", None, "config_yaml.yaml"),
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


@pytest.mark.parametrize("family,mem_type,configuration,blocks", FULL_LIST_TO_TEST)
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
        ("mimxrt595s", [("flexspi_nor", "xip_crc")]),
        ("mimxrt685s", [("flexspi_nor", "xip")]),
        ("lpc55s36", ["flexspi_nor", "internal"]),
        ("mimxrt1010", ["flexspi_nor"]),
        ("mimxrt1015", ["flexspi_nor"]),
        ("mimxrt1024", ["flexspi_nor"]),
        ("mimxrt1040", ["flexspi_nor"]),
        ("mimxrt1050", [("flexspi_nor", "fcb_bee_hab")]),
        ("mimxrt1064", ["flexspi_nor"]),
        ("mimxrt1166", ["flexspi_nor", "semc_nand", "flexspi_nand"]),
        ("mimxrt1176", [("flexspi_nor", "0x00_pattern"), "semc_nand", "flexspi_nand"]),
        ("mimxrt1189", [("flexspi_nor", "no_xmcd")]),
        ("mcxn947", [("flexspi_nor", "full")]),
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
        ("mimxrt595s", "mimxrt595s/flexspi_nor/xip_crc/merged_image.bin", "flexspi_nor"),
        ("lpc55s36", "lpc55s36/internal/merged_image.bin", "internal"),
        ("lpc55s36", "mimxrt595s/flexspi_nor/xip_crc/merged_image.bin", None),
        ("mimxrt1024", "mimxrt595s/flexspi_nor/xip_crc/merged_image.bin", None),
        ("mimxrt1189", "mimxrt595s/flexspi_nor/xip_crc/merged_image.bin", None),
        ("mimxrt1166", "mimxrt1166/flexspi_nor/merged_image.bin", "flexspi_nor"),
        ("mimxrt1166", "mimxrt1166/flexspi_nand/merged_image.bin", "flexspi_nand"),
        ("mimxrt1166", "mimxrt1166/semc_nand/merged_image.bin", "flexspi_nand"),
        ("mcxn947", "mcxn947/flexspi_nor/full/merged_image.bin", "flexspi_nor"),
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
    "family,input_path,expected_mem_type",
    [
        ("mimxrt595s", "mimxrt595s/flexspi_nor/xip_crc/merged_image.bin", "flexspi_nor"),
        ("lpc55s36", "lpc55s36/internal/merged_image.bin", "internal"),
        ("mimxrt1166", "mimxrt1166/flexspi_nor/merged_image.bin", "flexspi_nor"),
        ("mimxrt1166", "mimxrt1166/flexspi_nand/merged_image.bin", "flexspi_nand"),
        ("mimxrt1166", "mimxrt1166/semc_nand/merged_image.bin", "flexspi_nand"),
        ("mcxn947", "mcxn947/flexspi_nor/full/merged_image.bin", "flexspi_nor"),
    ],
)
def test_nxpimage_bimg_parse_autodetect_mem_type_cli(
    cli_runner: CliRunner, tmpdir, data_dir, family, input_path, expected_mem_type
):
    input_binary_path = os.path.join(data_dir, "bootable_image", input_path)

    with use_working_directory(data_dir):
        cmd = [
            "bootable-image",
            "parse",
            "-f",
            family,
            "-b",
            input_binary_path,
            "-o",
            str(tmpdir),
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        bimg_config = os.path.join(tmpdir, f"bootable_image_{family}_{expected_mem_type}.yaml")
        assert os.path.isfile(bimg_config)
        load_configuration(bimg_config)


@pytest.mark.parametrize(
    "family,mem_type,configuration,blocks",
    [
        ("mcxn947", "flexspi_nor", "full", ["fcb", "mbi"]),
        ("mcxn947", "flexspi_nor", "starting_fcb", ["fcb", "mbi"]),
        ("mcxn947", "flexspi_nor", "starting_mbi", ["mbi"]),
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
    bimg_bin = os.path.join(data_dir, "bootable_image", "lpc55s36", "internal", "merged_image.bin")
    bimg = BootableImage.parse(load_binary(bimg_bin), "lpc55s36")
    assert bimg.mem_type == "internal"
    # One warning regarding multiple mem types is shown
    # spi_recovery_mbi and internal should fit
    assert len(caplog.messages) == 1


def test_get_segment(data_dir):
    bimg_bin = os.path.join(
        data_dir, "bootable_image", "mimxrt595s", "flexspi_nor", "xip_plain", "merged_image.bin"
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
    family = "mimxrt595s"
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
        ("mcxn947", "flexspi_nor", "full", 0x0, 3),
        ("mcxn947", "flexspi_nor", "starting_fcb", 0x400, 3),
        ("mcxn947", "flexspi_nor", "starting_mbi", 0x1000, 1),
    ],
)
def test_nxpimage_bimg_parse_image_adjustment(
    data_dir, family, mem_type, configuration, init_offset, segments_count
):
    input_binary_path = os.path.join(
        data_dir, "bootable_image", family, mem_type, configuration, "merged_image.bin"
    )
    input_binary = load_binary(input_binary_path)
    bimg = BootableImage.parse(input_binary, family, MemoryType.from_label(mem_type))
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
    memory_type = MemoryType.from_label(mem_type)
    if actual_offset is not None:
        bimg = BootableImage(family=family, mem_type=memory_type, init_offset=init_offset)
        assert bimg.init_offset == actual_offset
        if isinstance(init_offset, int):
            bimg = BootableImage(family=family, mem_type=memory_type)
            bimg.init_offset = init_offset
            assert bimg.init_offset == actual_offset
    else:
        with pytest.raises(SPSDKError):
            BootableImage(family=family, mem_type=memory_type, init_offset=init_offset)
        if isinstance(init_offset, int):
            with pytest.raises(SPSDKError):
                bimg = BootableImage(family=family, mem_type=memory_type)
                bimg.init_offset = init_offset


def test_nxpimage_bimg_segments_index_is_updated(data_dir):
    config_dir = os.path.join(data_dir, "bootable_image", "mcxn947", "flexspi_nor", "starting_fcb")
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
        ("mcxn947", "flexspi_nor", "full"),
        ("mcxn947", "flexspi_nor", "starting_fcb"),
        ("mcxn947", "flexspi_nor", "starting_mbi"),
    ],
)
def test_nxpimage_bimg_parse_export(data_dir, family, mem_type, configuration):
    input_binary_path = os.path.join(
        data_dir, "bootable_image", family, mem_type, configuration, "merged_image.bin"
    )
    input_binary = load_binary(input_binary_path)
    bimg = BootableImage.parse(input_binary, family, MemoryType.from_label(mem_type))
    assert len(bimg.export()) == len(input_binary)


def test_bimg_get_supported_memory_types_all():
    mem_types = BootableImage.get_supported_memory_types()
    for mem_type in mem_types:
        assert mem_type in MemoryType
    # contains only unique values
    assert len(set(mem_types)) == len(mem_types)


@pytest.mark.parametrize(
    "family,mem_types",
    [
        (
            "mcxn9xx",
            [
                MemoryType.FLEXSPI_NOR,
                MemoryType.RECOVERY_SPI_SB31,
                MemoryType.RECOVERY_SPI_MBI,
                MemoryType.INTERNAL,
            ],
        ),
    ],
)
def test_bimg_get_supported_memory_types_family(family, mem_types):
    ret_mem_types = BootableImage.get_supported_memory_types(family)
    assert ret_mem_types == mem_types


@pytest.mark.parametrize("family,mem_type,configuration,blocks", FULL_LIST_TO_TEST)
def test_nxpimage_bimg_verify(
    cli_runner: CliRunner, tmpdir, data_dir, family, mem_type, configuration, blocks
):
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", family, mem_type)
        if configuration:
            config_dir = os.path.join(config_dir, configuration)
        input_binary = os.path.join(config_dir, "merged_image.bin")
        cmd = f"bootable-image verify -f {family} -m {mem_type} -b {input_binary} -p"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0)
        if mem_type == "flexspi_nor":
            cmd = f"bootable-image verify -f {family} -m serial_downloader -b {input_binary} -p"
            cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=1)
