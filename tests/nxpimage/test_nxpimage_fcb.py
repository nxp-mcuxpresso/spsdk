#!/usr/bin/env python
#
# Copyright 2022-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for FCB functionality in nxpimage application.

This module contains comprehensive tests for the FCB (Flexspi Configuration Block)
related features of the nxpimage command-line tool, including export operations,
CLI parsing, template generation, and error handling scenarios.
"""

import filecmp
import os
from typing import Any

import pytest

from spsdk.apps import nxpimage
from spsdk.exceptions import SPSDKError
from spsdk.image.fcb.fcb import FCB
from spsdk.image.mem_type import MemoryType
from spsdk.image.xmcd.xmcd import XMCD, ConfigurationBlockType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision, get_db
from spsdk.utils.misc import load_configuration, use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", "flexspi_nor"),
        ("rt6xx", "flexspi_nor"),
        ("mimxrt798s", "xspi_nor"),
        ("rt105x", "flexspi_nor"),
        ("rt106x", "flexspi_nor"),
        ("rt117x", "flexspi_nor"),
        ("lpc55s3x", "flexspi_nor"),
        ("mcxn9xx", "flexspi_nor"),
    ],
)
def test_nxpimage_fcb_export(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, mem_type: str
) -> None:
    """Test FCB export functionality using CLI runner.

    This test verifies that the FCB (Flash Configuration Block) export command
    works correctly by comparing the exported binary file with the expected
    reference file.

    :param cli_runner: CLI runner instance for executing commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Path to test data directory containing reference files.
    :param family: Target MCU family name.
    :param mem_type: Memory type for FCB configuration.
    """
    with use_working_directory(data_dir):
        config_file = os.path.join(data_dir, "fcb", family, f"fcb_{family}_{mem_type}.yaml")
        out_file = os.path.join(tmpdir, f"fcb_{family}_exported.bin")
        cmd = ["bootable-image", "fcb", "export", "-c", config_file, "-o", out_file]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(out_file)
        assert filecmp.cmp(
            os.path.join(data_dir, "fcb", family, "fcb.bin"),
            out_file,
            shallow=False,
        )


@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", "flexspi_nor"),
        (
            "rt6xx",
            "flexspi_nor",
        ),
        ("mimxrt798s", "xspi_nor"),
        ("rt105x", "flexspi_nor"),
        ("rt106x", "flexspi_nor"),
        ("rt117x", "flexspi_nor"),
        ("lpc55s3x", "flexspi_nor"),
        ("mcxn9xx", "flexspi_nor"),
    ],
)
def test_nxpimage_fcb_parse_cli(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, mem_type: str
) -> None:
    """Test FCB parse CLI command functionality.

    This test verifies that the FCB (Flash Configuration Block) parse command
    works correctly through the CLI interface. It creates a temporary output
    file, runs the parse command with specified family and memory type parameters,
    and validates that the output configuration file is generated successfully.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Base directory containing test data files
    :param family: Target MCU family name for FCB parsing
    :param mem_type: Memory type specification for FCB configuration
    """
    with use_working_directory(data_dir):
        data_folder = os.path.join(data_dir, "fcb", family)
        binary_path = os.path.join(data_folder, "fcb.bin")
        out_config = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        cmd = [
            "bootable-image",
            "fcb",
            "parse",
            "-f",
            family,
            "-m",
            mem_type,
            "-b",
            binary_path,
            "-o",
            out_config,
        ]
        cli_runner.invoke(nxpimage.main, cmd)

        assert os.path.isfile(out_config)


@pytest.mark.parametrize(
    "family,mem_types",
    [
        ("mimxrt595s", ["flexspi_nor"]),
        ("mimxrt685s", ["flexspi_nor"]),
        ("mimxrt1010", ["flexspi_nor"]),
        ("mimxrt1015", ["flexspi_nor"]),
        ("mimxrt1024", ["flexspi_nor"]),
        ("mimxrt1040", ["flexspi_nor"]),
        ("mimxrt1050", ["flexspi_nor"]),
        ("mimxrt1064", ["flexspi_nor"]),
        ("mimxrt1166", ["flexspi_nor"]),
        ("mimxrt1176", ["flexspi_nor"]),
        ("mimxrt1189", ["flexspi_nor"]),
        ("lpc55s36", ["flexspi_nor"]),
        ("rw612", ["flexspi_nor"]),
        ("mcxn947", ["flexspi_nor"]),
        ("lpc5536", ["flexspi_nor"]),
        ("mimxrt2662", ["xspi_nor", "xspi_nand"]),
        ("mimxrt798s", ["xspi_nor"]),
    ],
)
def test_nxpimage_fcb_template_cli(
    cli_runner: CliRunner, tmpdir: Any, family: str, mem_types: list[str]
) -> None:
    """Test FCB template CLI command functionality.

    Verifies that the bootable-image fcb get-templates command correctly generates
    FCB template files for the specified family and memory types.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param family: Target MCU family name.
    :param mem_types: List of memory types to verify template generation for.
    """
    cmd = f"bootable-image fcb get-templates -f {family} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())

    for mem_type in mem_types:
        template_name = os.path.join(tmpdir, f"fcb_{family}_{mem_type}.yaml")
        assert os.path.isfile(template_name)


@pytest.mark.parametrize(
    "binary,fail",
    [
        (b"0" * 512, True),
        (b"FCFB" + b"0" * 507, True),
        (b"FCFB" + b"0" * 508, False),
        (b"FCFB" + b"0" * 512, False),
        (b"CFBF" + b"0" * 512, False),
    ],
)
@pytest.mark.parametrize(
    "family,mem_type",
    [
        ("rt5xx", MemoryType.FLEXSPI_NOR),
        ("rt117x", MemoryType.FLEXSPI_NOR),
        ("mimxrt1189", MemoryType.FLEXSPI_NOR),
    ],
)
def test_fcb_parse_invalid(binary: bytes, fail: bool, family: str, mem_type: MemoryType) -> None:
    """Test FCB parsing with invalid binary data.

    This test function validates the FCB (Flash Configuration Block) parsing behavior
    when provided with potentially invalid binary data. It checks whether parsing
    should fail or succeed based on the expected outcome.

    :param binary: Binary data to be parsed as FCB.
    :param fail: Flag indicating whether parsing is expected to fail.
    :param family: Target MCU family identifier string.
    :param mem_type: Memory type specification for FCB parsing.
    :raises SPSDKError: When fail is True and parsing encounters an error (expected behavior).
    """
    if fail:
        with pytest.raises(SPSDKError):
            FCB.parse(binary, family=FamilyRevision(family), mem_type=mem_type)
    else:
        FCB.parse(binary, family=FamilyRevision(family), mem_type=mem_type)


@pytest.mark.parametrize(
    "family,mem_type,is_valid",
    [
        ("mimxrt798s", "flexspi_nor", False),
        ("mimxrt798s", "xspi_nor", True),
        ("mimxrt798s", None, True),
    ],
)
def test_default_memory_type(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, family: str, mem_type: str, is_valid: bool
) -> None:
    """Test default memory type handling in FCB parse command.

    This test verifies that the FCB parse command correctly handles different memory types
    and validates the expected behavior for both valid and invalid memory type configurations.

    :param cli_runner: CLI test runner instance for executing commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data files.
    :param family: Target MCU family name for FCB parsing.
    :param mem_type: Memory type parameter to test (empty string for default).
    :param is_valid: Expected validity of the command execution.
    """
    binary_path = os.path.join(data_dir, "fcb", family, "fcb.bin")
    cmd = f"bootable-image fcb parse -f {family} -b {binary_path} -o {tmpdir}/output.yaml"
    if mem_type:
        cmd += f" -m {mem_type}"
    cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0 if is_valid else -1)


@pytest.mark.parametrize("family", ["mimxrt2660", "mimxrt2661", "mimxrt2662", "mimxrt2663"])
def test_mimxrt266x_fcb_layout(family: str) -> None:
    """Test that RT266x families expose the XSPI NOR FCB with the expected ROM layout size.

    :param family: Target MCU family name from the RT266x group.
    """
    fcb = FCB(family=FamilyRevision(family), mem_type=MemoryType.XSPI_NOR)
    assert fcb.size == 0x260


@pytest.mark.parametrize("family", ["mimxrt2660", "mimxrt2661", "mimxrt2662", "mimxrt2663"])
def test_mimxrt266x_fcb_export_parse(family: str) -> None:
    """Test RT266x XSPI NOR FCB export and parse round-trip.

    :param family: Target MCU family name from the RT266x group.
    """
    family_rev = FamilyRevision(family)
    fcb = FCB(family=family_rev, mem_type=MemoryType.XSPI_NOR)
    data = fcb.export()
    assert len(data) == 0x260

    parsed = FCB.parse(data, family=family_rev, mem_type=MemoryType.XSPI_NOR)
    assert parsed.export() == data

    reloaded = FCB.load_from_config(fcb.get_config())
    assert reloaded.export() == data


@pytest.mark.parametrize("family", ["mimxrt2660", "mimxrt2661", "mimxrt2662", "mimxrt2663"])
def test_mimxrt266x_xmcd_supported(family: str) -> None:
    """Test that RT266x families expose the XSPI RAM XMCD support.

    :param family: Target MCU family name from the RT266x group.
    """
    supported = [str(fam.name) for fam in XMCD.get_supported_families()]
    assert family in supported

    xmcd = XMCD(
        family=FamilyRevision(family),
        mem_type=MemoryType.XSPI_RAM,
        config_type=ConfigurationBlockType.SIMPLIFIED,
    )
    data = xmcd.export()
    assert data
    assert XMCD.parse(data, family=FamilyRevision(family)).export() == data


MIMX9596_FCB_PRESETS = [
    "mt35x_octal_ddr_200mhz",
    "mt35x_octal_ddr_133mhz",
    "w25q512nw_single_sdr_133mhz",
]


def test_fcb_presets_list() -> None:
    """Test that FCB presets are defined only for families having them in the database."""
    assert list(FCB.get_presets(FamilyRevision("mimx9596"))) == MIMX9596_FCB_PRESETS
    assert FCB.get_presets(FamilyRevision("mimxrt1189")) == {}


def test_fcb_presets_stored_in_separate_file() -> None:
    """Test that FCB presets are loaded from a separate data file, not stored inline in database."""
    family = FamilyRevision("mimx9596")
    mem_type_cfg = FCB.get_memory_types_config(family)[MemoryType.FLEXSPI_NOR.label]
    assert "presets" not in mem_type_cfg
    presets_file = get_db(family).get_file_path(
        FCB.FEATURE, ["mem_types", MemoryType.FLEXSPI_NOR.label, "presets_file"]
    )
    assert os.path.isfile(presets_file)
    assert FCB.get_presets(family) == load_configuration(presets_file)


@pytest.mark.parametrize("preset", MIMX9596_FCB_PRESETS)
def test_fcb_preset_export(cli_runner: CliRunner, tmpdir: Any, data_dir: str, preset: str) -> None:
    """Test FCB export from a configuration using only the preset of a standard memory.

    The reference binaries contain the FCB of the standard memory in the first 0x1FC bytes;
    the last word is kept at its reset value.

    :param cli_runner: CLI runner instance for executing commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Path to test data directory containing reference files.
    :param preset: Name of the FCB preset.
    """
    config_file = os.path.join(tmpdir, "fcb_preset.yaml")
    with open(config_file, "w", encoding="utf-8") as f:
        f.write(f"family: mimx9596\ntype: flexspi_nor\npreset: {preset}\n")
    out_file = os.path.join(tmpdir, "fcb.bin")
    cmd = ["bootable-image", "fcb", "export", "-c", config_file, "-o", out_file]
    cli_runner.invoke(nxpimage.main, cmd)
    assert filecmp.cmp(
        os.path.join(data_dir, "fcb", "mimx9596", f"fcb_{preset}.bin"), out_file, shallow=False
    )


def test_fcb_preset_with_settings_override() -> None:
    """Test that FCB settings are applied on top of the preset values."""
    config = Config(
        {
            "family": "mimx9596",
            "type": "flexspi_nor",
            "preset": "mt35x_octal_ddr_200mhz",
            "fcb_settings": {"serialClkFreq": "0x06"},
        }
    )
    config.check(FCB.get_validation_schemas_from_cfg(config), check_unknown_props=True)
    fcb = FCB.load_from_config(config)
    expected = FCB(FamilyRevision("mimx9596"), MemoryType.FLEXSPI_NOR)
    expected.apply_preset("mt35x_octal_ddr_133mhz")
    assert fcb.export() == expected.export()


@pytest.mark.parametrize(
    "config",
    [
        {"family": "mimx9596", "type": "flexspi_nor"},
        {"family": "mimx9596", "type": "flexspi_nor", "preset": "unknown_memory"},
        {"family": "mimxrt1189", "type": "flexspi_nor", "preset": "mt35x_octal_ddr_200mhz"},
    ],
)
def test_fcb_preset_invalid_config(config: dict[str, Any]) -> None:
    """Test that a configuration without settings or with an unknown preset is rejected.

    :param config: Invalid FCB configuration.
    """
    cfg = Config(config)
    with pytest.raises(SPSDKError):
        cfg.check(FCB.get_validation_schemas_from_cfg(cfg), check_unknown_props=True)
    with pytest.raises(SPSDKError):
        FCB.load_from_config(cfg)


def test_fcb_apply_unknown_preset() -> None:
    """Test that applying an unknown preset raises an error listing available presets."""
    fcb = FCB(FamilyRevision("mimx9596"), MemoryType.FLEXSPI_NOR)
    with pytest.raises(SPSDKError, match="mt35x_octal_ddr_200mhz"):
        fcb.apply_preset("unknown_memory")


def test_nxpimage_fcb_template_presets_cli(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test that get-templates with presets creates loadable configurations of all presets.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    """
    cmd = f"bootable-image fcb get-templates -f mimx9596 --presets --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(os.path.join(tmpdir, "fcb_mimx9596_flexspi_nor.yaml"))
    for preset in MIMX9596_FCB_PRESETS:
        cfg_file = os.path.join(tmpdir, f"fcb_mimx9596_flexspi_nor_{preset}.yaml")
        config = Config.create_from_file(cfg_file)
        config.check(FCB.get_validation_schemas_from_cfg(config), check_unknown_props=True)
        expected = FCB(FamilyRevision("mimx9596"), MemoryType.FLEXSPI_NOR)
        expected.apply_preset(preset)
        assert FCB.load_from_config(config).export() == expected.export()


def test_nxpimage_fcb_template_presets_cli_no_presets(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test that get-templates with presets creates only the template for families without presets.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    """
    cmd = f"bootable-image fcb get-templates -f mimxrt1189 --presets --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.listdir(tmpdir) == ["fcb_mimxrt1189_flexspi_nor.yaml"]


def _crc32_mpeg2(data: bytes) -> int:
    """Reference CRC32 MPEG2 implementation used by ROM to check XSPI NAND FCB.

    :param data: Input data.
    :return: Calculated checksum.
    """
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else crc << 1
            crc &= 0xFFFFFFFF
    return crc


@pytest.mark.parametrize("family", ["mimxrt2660", "mimxrt2661", "mimxrt2662", "mimxrt2663"])
def test_mimxrt266x_xspi_nand_fcb_layout(family: str) -> None:
    """Test RT266x XSPI NAND FCB layout, tag, embedded XSPI config block and checksum.

    :param family: Target MCU family name from the RT266x group.
    """
    family_rev = FamilyRevision(family)
    assert MemoryType.XSPI_NAND in FCB.get_supported_memory_types(family_rev)
    fcb = FCB(family=family_rev, mem_type=MemoryType.XSPI_NAND)
    assert fcb.size == 0x400
    data = fcb.export()
    assert len(data) == 0x400
    assert int.from_bytes(data[0x04:0x08], "little") == 0x4E464342  # fingerprint 'NFCB'
    assert int.from_bytes(data[0x08:0x0C], "little") == 1
    assert int.from_bytes(data[0x14:0x18], "little") == 1
    # Serial NAND configuration block (common XSPI memory configuration block) at 0x100
    assert data[0x100:0x104] == FCB.TAG
    assert int.from_bytes(data[0x104:0x108], "little") == 0x56010000
    assert data[0x144] == 2  # deviceType: Serial NAND
    assert int.from_bytes(data[:4], "little") == _crc32_mpeg2(data[4:])


def test_mimxrt266x_xspi_nand_fcb_export_parse() -> None:
    """Test RT266x XSPI NAND FCB round-trip and checksum update on configuration change."""
    family = FamilyRevision("mimxrt2662")
    fcb = FCB(family=family, mem_type=MemoryType.XSPI_NAND)
    config = fcb.get_config()
    config["fcb_settings"]["firmwareCopies"] = 2
    config["fcb_settings"]["firmwareInfoTable_0_startPage"] = 0x100
    config["fcb_settings"]["firmwareInfoTable_1_startPage"] = 0x200
    config["fcb_settings"]["pageDataSize"] = 2048
    config["fcb_settings"]["pagesPerBlock"] = 64
    fcb = FCB.load_from_config(config)
    data = fcb.export()
    assert int.from_bytes(data[0x40:0x44], "little") == 0x100
    assert int.from_bytes(data[0x48:0x4C], "little") == 0x200
    assert int.from_bytes(data[0x328:0x32C], "little") == 2048
    assert int.from_bytes(data[:4], "little") == _crc32_mpeg2(data[4:])

    parsed = FCB.parse(data, family=family, mem_type=MemoryType.XSPI_NAND)
    assert parsed.export() == data
    assert FCB.load_from_config(parsed.get_config()).export() == data
    assert FCB.parse(
        b"\xff" * 0x10 + data, offset=0x10, family=family, mem_type=MemoryType.XSPI_NAND
    )


@pytest.mark.parametrize(
    "offset,value",
    [
        (0x00, 0x01),  # corrupted checksum
        (0x05, 0x00),  # corrupted fingerprint
        (0x200, 0x01),  # corrupted data
    ],
)
def test_mimxrt266x_xspi_nand_fcb_parse_invalid(offset: int, value: int) -> None:
    """Test RT266x XSPI NAND FCB parse fails on corrupted fingerprint or checksum.

    :param offset: Offset of the modified byte.
    :param value: Value XORed into the modified byte.
    """
    family = FamilyRevision("mimxrt2662")
    data = bytearray(FCB(family=family, mem_type=MemoryType.XSPI_NAND).export())
    data[offset] ^= value if value else 0xFF
    with pytest.raises(SPSDKError):
        FCB.parse(bytes(data), family=family, mem_type=MemoryType.XSPI_NAND)
    with pytest.raises(SPSDKError):
        FCB.parse(bytes(data[:0x3FF]), family=family, mem_type=MemoryType.XSPI_NAND)


def test_mimxrt266x_xspi_nand_fcb_cli(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test RT266x XSPI NAND FCB get-templates, export and parse via nxpimage CLI.

    :param cli_runner: CLI runner instance for executing commands.
    :param tmpdir: Temporary directory for output files.
    """
    cmd = f"bootable-image fcb get-templates -f mimxrt2662 --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    template = os.path.join(tmpdir, "fcb_mimxrt2662_xspi_nand.yaml")
    assert os.path.isfile(template)

    out_bin = os.path.join(tmpdir, "fcb_nand.bin")
    cli_runner.invoke(
        nxpimage.main, ["bootable-image", "fcb", "export", "-c", template, "-o", out_bin]
    )
    with open(out_bin, "rb") as f:
        data = f.read()
    assert len(data) == 0x400
    assert int.from_bytes(data[:4], "little") == _crc32_mpeg2(data[4:])

    out_cfg = os.path.join(tmpdir, "fcb_nand.yaml")
    cmd = f"bootable-image fcb parse -f mimxrt2662 -m xspi_nand -b {out_bin} -o {out_cfg}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(out_cfg)
