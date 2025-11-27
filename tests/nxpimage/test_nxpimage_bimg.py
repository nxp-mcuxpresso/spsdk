#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test suite for SPSDK nxpimage bootable image functionality.

This module contains comprehensive tests for the bootable image (bimg) component
of the nxpimage application, covering CLI operations, image parsing, merging,
verification, and memory type detection functionality.
"""

import filecmp
import logging
import os
from typing import Any, Optional, Union

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.ahab.ahab_data import AhabTargetMemory
from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.bootable_image.segments import BootableImageSegment
from spsdk.image.mem_type import MemoryType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, load_configuration, use_working_directory
from spsdk.utils.verifier import Verifier, VerifierRecord, VerifierResult
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
    ("mimxrt798s", "xspi_nor", None, ["fcb", "mbi"]),
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
        ("flexspi_nor", "mimxrt1176", "as_yaml", "config.yaml"),
        ("flexspi_nand", "mimxrt1166", None, "config.yaml"),
        ("flexspi_nand", "mimxrt1176", None, "config.yaml"),
        ("flexspi_nand", "mimxrt1176", None, "config_yaml.yaml"),
    ],
)
def test_nxpimage_bimg_merge(
    cli_runner: CliRunner,
    tmpdir: Any,
    data_dir: str,
    mem_type: str,
    family: str,
    configuration: Optional[str],
    config_file: str,
) -> None:
    """Test bootable image merge functionality using CLI.

    This test verifies that the nxpimage CLI can successfully export a bootable image
    using a configuration file and that the output matches the expected merged image.
    The test handles different memory types, chip families, and optional configurations.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data files.
    :param mem_type: Memory type for the bootable image (e.g., 'flexspi_nor').
    :param family: Target chip family name.
    :param configuration: Optional configuration subdirectory name.
    :param config_file: Name of the configuration file to use.
    :raises AssertionError: If output file is not created or doesn't match expected content.
    """
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", family, mem_type)
        if configuration:
            config_dir = os.path.join(config_dir, configuration)
        config_file_path = os.path.join(config_dir, config_file)
        out_file = os.path.join(tmpdir, f"bimg_{family}_merged.bin")
        cmd = ["bootable-image", "export", "-c", config_file_path, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(config_dir, "merged_image.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize("family,mem_type,configuration,blocks", FULL_LIST_TO_TEST)
def test_nxpimage_bimg_parse_cli(
    cli_runner: CliRunner,
    tmpdir: Any,
    data_dir: str,
    family: str,
    mem_type: str,
    configuration: Optional[str],
    blocks: list[str],
) -> None:
    """Test CLI parsing functionality for bootable image commands.

    This test verifies that the nxpimage bootable-image parse command correctly
    processes input binary files and generates the expected configuration and
    segment files. It compares the generated configuration against a reference
    and validates that extracted segments match the original files.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for bootable image processing.
    :param mem_type: Memory type specification for the bootable image.
    :param configuration: Optional configuration variant name.
    :param blocks: List of block names to validate in the parsed output.
    """
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
def test_nxpimage_bimg_template_cli(
    cli_runner: CliRunner,
    tmpdir: Any,
    data_dir: str,
    family: str,
    configs: list[Union[str, tuple[str, str]]],
) -> None:
    """Test CLI command for generating bootable image templates.

    This test verifies that the nxpimage CLI can successfully generate bootable image
    configuration templates for a given family and memory types. It checks that the
    generated templates exist and have the same structure as reference configurations.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for template generation.
    :param configs: List of memory type configurations, either as strings or tuples of (mem_type, config_dir).
    """
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
        generated.pop("post_export")
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
def test_nxpimage_bimg_parse_autodetect_mem_type(
    data_dir: str, family: str, input_path: str, expected_mem_type: Optional[str]
) -> None:
    """Test bootable image parsing with automatic memory type detection.

    This test verifies that the BootableImage.parse method can correctly auto-detect
    the memory type from a binary file for a given family. When a valid memory type
    is expected, it checks that parsing succeeds and returns the correct memory type
    with zero init offset. When no valid memory type is expected, it verifies that
    parsing raises an SPSDKError.

    :param data_dir: Base directory containing test data files
    :param family: Target MCU family name for parsing
    :param input_path: Relative path to the bootable image binary file within data_dir
    :param expected_mem_type: Expected memory type to be detected, or None if parsing should fail
    :raises SPSDKError: When expected_mem_type is None and parsing fails as expected
    """
    input_binary_path = os.path.join(data_dir, "bootable_image", input_path)
    input_binary = load_binary(input_binary_path)
    family_rev = FamilyRevision(family)
    if expected_mem_type:
        bimg = BootableImage.parse(input_binary, family_rev)
        assert bimg.init_offset == 0
        assert bimg.mem_type == expected_mem_type
    else:
        with pytest.raises(SPSDKError):
            BootableImage.parse(input_binary, family_rev)


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
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    input_path: str,
    expected_mem_type: str,
) -> None:
    """Test CLI auto-detection of memory type during bootable image parsing.

    This test verifies that the nxpimage CLI can automatically detect the correct
    memory type when parsing a bootable image and generates the appropriate
    configuration file with the expected memory type in its filename.

    :param cli_runner: CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Directory containing test data files.
    :param family: Target MCU family name.
    :param input_path: Relative path to input bootable image file.
    :param expected_mem_type: Expected memory type to be auto-detected.
    """
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
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    mem_type: str,
    configuration: str,
    blocks: list[str],
) -> None:
    """Test nxpimage bootable image parse command with incomplete CLI parameters.

    This test verifies that the bootable image parse command can successfully parse
    a binary file and generate the correct configuration and segment files, even
    when using minimal CLI parameters. It compares the generated output against
    reference files to ensure correctness.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for bootable image.
    :param mem_type: Memory type specification for the bootable image.
    :param configuration: Configuration variant name for the test case.
    :param blocks: List of block names to verify in the parsed output.
    """
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


def test_find_the_exact_layout_match_first(caplog: Any, data_dir: str) -> None:
    """Test that exact layout match is found first when multiple memory types are possible.

    This test verifies that when parsing a bootable image that could match multiple
    memory types, the system correctly selects the most appropriate one (internal memory)
    and logs a warning about the multiple possibilities.

    :param caplog: Pytest fixture for capturing log messages during test execution.
    :param data_dir: Path to the test data directory containing bootable image files.
    :raises AssertionError: If the parsed image doesn't have expected memory type or warning message.
    """
    caplog.set_level(logging.WARNING)
    bimg_bin = os.path.join(data_dir, "bootable_image", "lpc55s36", "internal", "merged_image.bin")
    bimg = BootableImage.parse(load_binary(bimg_bin), FamilyRevision("lpc55s36"))
    assert bimg.mem_type == "internal"
    # One warning regarding multiple mem types is shown
    # spi_recovery_mbi and internal should fit
    assert next(
        msg
        for msg in caplog.messages
        if msg
        == 'Multiple possible memory types detected: "Internal memory", "Recovery SPI with MBI".The "Internal memory" memory type will be used.'
    )


def test_get_segment(data_dir: str) -> None:
    """Test bootable image segment retrieval functionality.

    This test verifies that the BootableImage.get_segment() method correctly
    identifies and returns segments at their expected offsets within a bootable
    image binary file. It tests FCB, IMAGE_VERSION, and MBI segments.

    :param data_dir: Directory path containing test data files including the bootable image binary.
    """
    bimg_bin = os.path.join(
        data_dir, "bootable_image", "mimxrt595s", "flexspi_nor", "xip_plain", "merged_image.bin"
    )
    bimg = BootableImage.parse(load_binary(bimg_bin), FamilyRevision("rt5xx"))
    segments = {
        BootableImageSegment.FCB: 1024,
        BootableImageSegment.IMAGE_VERSION: 1536,
        BootableImageSegment.MBI: 4096,
    }
    for segment in segments:
        assert bimg.get_segment(segment).full_image_offset == segments[segment]


def test_image_info(data_dir: str) -> None:
    """Test bootable image information extraction functionality.

    This test verifies that the BootableImage.parse() method correctly extracts
    and provides image information for a MIMXRT595S bootable image, including
    validation of image metadata, offsets, patterns, and sub-image structure.

    :param data_dir: Path to the test data directory containing bootable image files.
    :raises AssertionError: If any of the image information validation checks fail.
    """
    family = "mimxrt595s"
    bimg_bin = os.path.join(
        data_dir, "bootable_image", family, "flexspi_nor", "xip_plain", "merged_image.bin"
    )
    bimg = BootableImage.parse(load_binary(bimg_bin), FamilyRevision(family))
    info = bimg.image_info()
    assert f"Bootable Image for {family}" in info.name
    assert f"Bootable Image for {family}" in info.image_name
    assert info.offset == 0
    assert info.pattern
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
    data_dir: str,
    family: str,
    mem_type: str,
    configuration: str,
    init_offset: int,
    segments_count: int,
) -> None:
    """Test parsing of bootable image with segment adjustment validation.

    This test verifies that a bootable image can be correctly parsed from a binary file
    and validates that the parsed image has the expected initialization offset and
    number of segments.

    :param data_dir: Base directory path containing test data files.
    :param family: Target MCU family name for the bootable image.
    :param mem_type: Memory type label (e.g., 'flexspi_nor', 'semc_nand').
    :param configuration: Configuration variant name for the test case.
    :param init_offset: Expected initialization offset value in the parsed image.
    :param segments_count: Expected number of segments in the parsed bootable image.
    """
    input_binary_path = os.path.join(
        data_dir, "bootable_image", family, mem_type, configuration, "merged_image.bin"
    )
    input_binary = load_binary(input_binary_path)
    bimg = BootableImage.parse(
        input_binary, FamilyRevision(family), MemoryType.from_label(mem_type)
    )
    assert bimg.init_offset == init_offset
    assert len(bimg.segments) == segments_count


def test_nxpimage_bimg_default_init_offset() -> None:
    """Test that default initialization offset is zero for all supported configurations.

    Verifies that BootableImage instances created with default parameters have an
    initialization offset of 0 for all combinations of supported families and
    memory types.
    """
    for family in BootableImage.get_supported_families():
        for mem_type in BootableImage.get_supported_memory_types(family):
            assert BootableImage(family=family, mem_type=mem_type).init_offset == 0


@pytest.mark.parametrize(
    "family_str,mem_type,init_offset,actual_offset",
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
def test_nxpimage_bimg_init_offset_setter(
    family_str: str,
    mem_type: str,
    init_offset: Union[int, BootableImageSegment],
    actual_offset: Optional[int],
) -> None:
    """Test BootableImage initialization and init_offset setter functionality.

    This test verifies that the BootableImage class correctly handles init_offset
    parameter during initialization and through the setter property. It tests both
    valid scenarios where the offset is accepted and invalid scenarios where
    SPSDKError should be raised.

    :param family_str: String representation of the target family.
    :param mem_type: Memory type label for the bootable image.
    :param init_offset: Initial offset value, either as integer or BootableImageSegment.
    :param actual_offset: Expected offset value after setting, None if error expected.
    :raises SPSDKError: When init_offset is invalid for the given family/memory type combination.
    """
    family = FamilyRevision(family_str)
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


def test_nxpimage_bimg_segments_index_is_updated(data_dir: str) -> None:
    """Test that bootable image segment indices are correctly updated when init_offset changes.

    This test verifies that when the init_offset of a bootable image is modified,
    the segment indices are properly recalculated and segments that fall below
    the new init_offset are automatically removed from the segments list.

    :param data_dir: Path to the test data directory containing bootable image configuration files.
    """
    config_dir = os.path.join(data_dir, "bootable_image", "mcxn947", "flexspi_nor", "starting_fcb")
    bimg = BootableImage.load_from_config(
        Config.create_from_file(os.path.join(config_dir, "config.yaml"))
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
def test_nxpimage_bimg_parse_export(
    data_dir: str, family: str, mem_type: str, configuration: str
) -> None:
    """Test parsing and exporting of bootable image binary data.

    This test verifies that a bootable image can be parsed from binary data
    and then exported back to binary format with the same length as the
    original input data.

    :param data_dir: Base directory path containing test data files
    :param family: Target MCU family identifier
    :param mem_type: Memory type label for the bootable image
    :param configuration: Configuration variant name for the test case
    :raises AssertionError: When exported binary length differs from input
    """
    input_binary_path = os.path.join(
        data_dir, "bootable_image", family, mem_type, configuration, "merged_image.bin"
    )
    input_binary = load_binary(input_binary_path)
    bimg = BootableImage.parse(
        input_binary, FamilyRevision(family), MemoryType.from_label(mem_type)
    )
    assert len(bimg.export()) == len(input_binary)


def test_bimg_get_supported_memory_types_all() -> None:
    """Test that get_supported_memory_types returns all valid memory types.

    Verifies that the BootableImage.get_supported_memory_types() method returns
    a list containing only valid MemoryType enum values and that all returned
    values are unique (no duplicates).

    :raises AssertionError: If any returned memory type is not a valid MemoryType
        enum value or if duplicate values are found in the list.
    """
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
def test_bimg_get_supported_memory_types_family(family: str, mem_types: list[MemoryType]) -> None:
    """Test that BootableImage returns correct supported memory types for a given family.

    Verifies that the get_supported_memory_types method of BootableImage class
    returns the expected list of memory types for the specified chip family.

    :param family: Name of the chip family to test.
    :param mem_types: Expected list of supported memory types for the family.
    """
    ret_mem_types = BootableImage.get_supported_memory_types(FamilyRevision(family))
    assert ret_mem_types == mem_types


@pytest.mark.parametrize("family,mem_type,configuration,blocks", FULL_LIST_TO_TEST)
def test_nxpimage_bimg_verify(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    family: str,
    mem_type: str,
    configuration: Optional[str],
    blocks: list[str],
) -> None:
    """Test nxpimage bootable-image verify command functionality.

    This test verifies that the bootable-image verify command works correctly
    for different family and memory type combinations. It tests both successful
    verification and expected failure cases (e.g., flexspi_nor with serial_downloader).

    :param cli_runner: CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for test files.
    :param data_dir: Directory containing test data files.
    :param family: Target MCU family name.
    :param mem_type: Memory type for bootable image.
    :param configuration: Optional configuration variant.
    :param blocks: List of block identifiers for the test.
    """
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


@pytest.mark.parametrize(
    "mem_type,family,configuration,config_file",
    [
        ("serial_downloader", "mimx9352", None, "config.yaml"),
    ],
)
def test_nxpimage_bimg_merge_post_export(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    mem_type: str,
    family: str,
    configuration: Optional[str],
    config_file: str,
) -> None:
    """Test bootable image export with post-export merge functionality.

    This test verifies that the nxpimage CLI can successfully export a bootable image
    with post-export processing enabled, and that the post-export output directory
    is created with the expected number of files.

    :param cli_runner: CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory path for test output files.
    :param data_dir: Base directory containing test data files.
    :param mem_type: Memory type for the bootable image configuration.
    :param family: Target MCU family for the bootable image.
    :param configuration: Optional configuration variant for the test.
    :param config_file: Configuration file name to use for the export.
    """
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", family, mem_type)
        if configuration:
            config_dir = os.path.join(config_dir, configuration)
        config_file_path = os.path.join(config_dir, config_file)
        out_file = os.path.join(tmpdir, f"bimg_{family}_merged.bin")
        cmd = [
            "bootable-image",
            "export",
            "-c",
            config_file_path,
            "-o",
            out_file,
            "-oc",
            f"post_export={os.path.join(tmpdir, 'output')}",
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)

        # assert that the output directory is created and is not empty
        assert os.path.exists(os.path.join(tmpdir, "output"))
        assert len(os.listdir(os.path.join(tmpdir, "output"))) == 4


def test_nxpimage_bimg_merge_custom_offset(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test bootable image merge functionality with custom offset configuration.

    This test verifies that the nxpimage CLI can successfully export a bootable image
    using a custom offset configuration file, and that the resulting binary contains
    valid AHAB images at the expected offsets.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Test data directory containing configuration files.
    :raises AssertionError: If output file is not created or AHAB images cannot be parsed.
    """
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", "mimx9352", "serial_downloader")
        config_file_path = os.path.join(config_dir, "config_custom_offset.yaml")
        out_file = os.path.join(tmpdir, "bimg_mimx9352_merged.bin")
        cmd = [
            "bootable-image",
            "export",
            "-c",
            config_file_path,
            "-o",
            out_file,
            "-oc",
            f"post_export={os.path.join(tmpdir, 'output')}",
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        bimg_bin = load_binary(out_file)
        ahab_1 = AHABImage.parse(
            bimg_bin,
            family=FamilyRevision("mimx9352"),
            target_memory=AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER.label,
        )
        assert ahab_1
        ahab_2 = AHABImage.parse(
            bimg_bin[0xA000:],
            family=FamilyRevision("mimx9352"),
            target_memory=AhabTargetMemory.TARGET_MEMORY_SERIAL_DOWNLOADER.label,
        )
        assert ahab_2


def test_nxpimage_bimg_parse_custom_offset(
    cli_runner: CliRunner, tmpdir: str, data_dir: str
) -> None:
    """Test parsing bootable image with custom offset configuration.

    This test verifies that the nxpimage CLI can correctly parse a bootable image
    binary file that contains a secondary image container set with a custom offset,
    and that the parsed configuration maintains the correct offset value.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory path for output files.
    :param data_dir: Base directory containing test data files.
    """
    with use_working_directory(data_dir):
        config_dir = os.path.join(data_dir, "bootable_image", "mimx9352", "serial_downloader")
        input_binary = os.path.join(config_dir, "merged_image_custom_offset.bin")
        cmd = [
            "bootable-image",
            "parse",
            "-m",
            "serial_downloader",
            "-f",
            "mimx9352",
            "-b",
            input_binary,
            "-o",
            str(tmpdir),
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        bimg_config = os.path.join(tmpdir, "bootable_image_mimx9352_serial_downloader.yaml")
        assert os.path.isfile(bimg_config)
        config = load_configuration(bimg_config)
        assert config.get("secondary_image_container_set")
        os.path.isfile(os.path.join(config_dir, config["secondary_image_container_set"]["path"]))
        assert config["secondary_image_container_set"]["offset"] == 40960


def test_verifier_add_record_range_hex_string() -> None:
    """Test the Verifier.add_record_range method with hexadecimal string values.

    Validates that the method correctly handles various hexadecimal string formats
    including lowercase and uppercase prefixes, range validation with min/max values,
    and proper error handling for invalid hexadecimal strings.

    :raises SPSDKError: When invalid hexadecimal strings are provided.
    """
    verifier = Verifier("Test Verifier")

    # Test valid hex string
    verifier.add_record_range("Valid hex", "0x1000")
    assert len(verifier.records) == 1
    assert isinstance(verifier.records[0], VerifierRecord)
    assert verifier.records[0].result == VerifierResult.SUCCEEDED
    assert verifier.records[0].value == "0x1000"

    # Test valid hex string uppercase
    verifier.add_record_range("Valid hex uppercase", "0X2000")
    assert len(verifier.records) == 2
    assert isinstance(verifier.records[1], VerifierRecord)
    assert verifier.records[1].result == VerifierResult.SUCCEEDED
    assert verifier.records[1].value == "0X2000"

    # Test hex string out of range (too high)
    verifier.add_record_range("Hex too high", "0xFFFFFFFF", max_val=1000)
    assert len(verifier.records) == 3
    assert isinstance(verifier.records[2], VerifierRecord)
    assert verifier.records[2].result == VerifierResult.ERROR
    assert "Higher than allowed" in str(verifier.records[2].value)

    # Test hex string out of range (too low)
    verifier.add_record_range("Hex too low", "0x10", min_val=100)
    assert len(verifier.records) == 4
    assert isinstance(verifier.records[3], VerifierRecord)
    assert verifier.records[3].result == VerifierResult.ERROR
    assert "Lower than allowed" in str(verifier.records[3].value)

    # Test invalid hex string - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Invalid hex", "0xGGGG")

    # Test non-hex string - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Non-hex string", "not_hex")


def test_verifier_add_record_range_hex_integration() -> None:
    """Test add_record_range hex functionality in context similar to bootable image.

    This integration test verifies that the Verifier can properly handle hexadecimal
    offset values when adding record ranges, simulating real bootable image scenarios
    where segment offsets are commonly expressed in hexadecimal format.

    :raises AssertionError: If any of the verification assertions fail during testing.
    """
    verifier = Verifier("Bootable Image Test")

    # Simulate segment offset verification with hex
    segment_offset = 0x1000
    hex_offset = f"0x{segment_offset:08X}"

    verifier.add_record_range("Offset in image", hex_offset)

    assert len(verifier.records) == 1
    assert isinstance(verifier.records[0], VerifierRecord)
    assert verifier.records[0].result == VerifierResult.SUCCEEDED
    assert verifier.records[0].value == hex_offset
    assert verifier.records[0].name == "Offset in image"


def test_verifier_add_record_range_hex_negative_scenarios() -> None:
    """Test add_record_range method with various invalid hex string scenarios.

    This test verifies that the Verifier.add_record_range method properly handles
    and rejects malformed hex strings, including empty strings, invalid characters,
    special characters, negative values, and decimal points. It also tests that
    extremely long hex values are handled gracefully by creating an ERROR record.

    :raises SPSDKError: When invalid hex string formats are provided to add_record_range.
    """
    verifier = Verifier("Negative Test Verifier")

    # Test empty hex string - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Empty hex", "0x")

    # Test hex string with only prefix - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Only prefix", "0X")

    # Test hex string with spaces - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Hex with spaces", "0x 1000")

    # Test hex string with invalid characters mixed in - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Mixed invalid chars", "0x12G34")

    # Test hex string with special characters - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Special chars", "0x12@34")

    # Test very long hex string (exceeds 32-bit range, should be ERROR)
    verifier.add_record_range("Very long hex", "0x" + "F" * 20)
    assert len(verifier.records) == 1
    assert isinstance(verifier.records[0], VerifierRecord)
    assert verifier.records[0].result == VerifierResult.ERROR
    assert "Higher than allowed" in str(verifier.records[0].value)

    # Test negative hex - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Negative hex", "-0x1000")

    # Test hex with decimal point - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Hex with decimal", "0x10.5")


def test_verifier_add_record_range_edge_cases() -> None:
    """Test edge cases for hex string handling in Verifier.add_record_range method.

    This test validates the behavior of the Verifier's add_record_range method when
    handling various edge cases including None values, empty strings, whitespace-only
    strings, case sensitivity in hex prefixes, and boundary value conditions.

    :raises SPSDKError: When empty string or whitespace-only string is provided as hex value.
    """
    verifier = Verifier("Edge Case Verifier")

    # Test None value (should work as before)
    verifier.add_record_range("None value", None)
    assert len(verifier.records) == 1
    assert isinstance(verifier.records[0], VerifierRecord)
    assert verifier.records[0].result == VerifierResult.ERROR
    assert verifier.records[0].value == "Doesn't exists"

    # Test empty string - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Empty string", "")

    # Test string with only whitespace - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Whitespace only", "   ")

    # Test case sensitivity issues (should work)
    verifier.add_record_range("Mixed case prefix", "0X1a2B")
    assert isinstance(verifier.records[1], VerifierRecord)
    assert len(verifier.records) == 2
    assert verifier.records[1].result == VerifierResult.SUCCEEDED

    # Test hex string that converts to zero
    verifier.add_record_range("Zero hex", "0x0", min_val=1)
    assert len(verifier.records) == 3
    assert isinstance(verifier.records[2], VerifierRecord)
    assert verifier.records[2].result == VerifierResult.ERROR
    assert "Lower than allowed" in str(verifier.records[2].value)


def test_verifier_add_record_range_boundary_conditions() -> None:
    """Test boundary conditions for Verifier.add_record_range method with hexadecimal string values.

    This test validates that the Verifier correctly handles edge cases including:
    - Maximum 32-bit values (0xFFFFFFFF)
    - Values exceeding 32-bit limits (0x100000000)
    - Minimum boundary values (0x0)
    - Values below specified minimum thresholds
    The test ensures proper error detection and success validation for boundary conditions
    in hexadecimal string parsing and range validation within the SPSDK verification system.
    """
    verifier = Verifier("Boundary Test Verifier")

    # Test maximum 32-bit value as hex
    max_32bit = "0xFFFFFFFF"
    verifier.add_record_range("Max 32-bit", max_32bit)
    assert len(verifier.records) == 1
    assert isinstance(verifier.records[0], VerifierRecord)
    assert verifier.records[0].result == VerifierResult.SUCCEEDED

    # Test value just over 32-bit limit
    over_32bit = "0x100000000"  # 2^32
    verifier.add_record_range("Over 32-bit", over_32bit)
    assert len(verifier.records) == 2
    assert isinstance(verifier.records[1], VerifierRecord)
    assert verifier.records[1].result == VerifierResult.ERROR
    assert "Higher than allowed" in str(verifier.records[1].value)

    # Test minimum boundary
    verifier.add_record_range("At min boundary", "0x0", min_val=0)
    assert len(verifier.records) == 3
    assert isinstance(verifier.records[2], VerifierRecord)
    assert verifier.records[2].result == VerifierResult.SUCCEEDED

    # Test just below minimum
    verifier.add_record_range("Below min", "0x9", min_val=10)
    assert len(verifier.records) == 4
    assert isinstance(verifier.records[3], VerifierRecord)
    assert verifier.records[3].result == VerifierResult.ERROR
    assert "Lower than allowed" in str(verifier.records[3].value)


def test_verifier_add_record_range_malformed_input() -> None:
    """Test various malformed input scenarios for Verifier.add_record_range method.

    This test validates that the add_record_range method properly handles and rejects
    various forms of malformed hexadecimal input strings by raising SPSDKError exceptions.
    The test covers scenarios including multiple prefixes, trailing/leading characters,
    unicode characters, and newline characters in hex strings.

    :raises SPSDKError: Expected exception for all malformed input test cases.
    """
    verifier = Verifier("Malformed Input Verifier")

    # Test multiple 0x prefixes - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Double prefix", "0x0x1000")

    # Test hex with trailing characters - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Trailing chars", "0x1000xyz")

    # Test hex with leading characters - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Leading chars", "abc0x1000")

    # Test unicode characters - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Unicode chars", "0x10🔥00")

    # Test newline in hex string - should raise SPSDKError
    with pytest.raises(SPSDKError):
        verifier.add_record_range("Newline in hex", "0x10\n00")
