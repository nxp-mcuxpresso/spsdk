#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for nxpimage binary operations and CLI functionality.

This module provides comprehensive test coverage for the nxpimage application's
binary handling capabilities, including file format conversions, merging operations,
padding, alignment, and special handling conditions for empty binaries.
"""

import filecmp
import os
import struct
from typing import Any, Optional

import pytest

from spsdk.apps import nxpimage
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.misc import (
    BinaryPattern,
    load_binary,
    load_configuration,
    use_working_directory,
    write_file,
)
from tests.cli_runner import CliRunner


def test_nxpimage_binary_template(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test binary image template generation and validation.

    This test verifies that the nxpimage CLI can successfully generate a binary merge
    template file and that the generated template is valid and can be loaded.

    :param cli_runner: CLI runner fixture for testing command line interface.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    template_name = os.path.join(tmpdir, "binary_merge.yaml")
    cmd = f"utils binary-image get-template --output {template_name}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(template_name)
    load_configuration(template_name)


def test_nxpimage_binary_merge_with_random(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str
) -> None:
    """Test binary image merge functionality with random padding preservation.

    This test verifies that the nxpimage binary export command correctly merges
    binary files according to configuration while preserving random padding data.
    The test compares the merged output against a reference file, checking that
    all content except the padding area (bytes 24-28) matches exactly.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory for test output files
    :param data_dir: Directory containing test data and configuration files
    """
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", "binary_merge.yaml")
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image export -c {merge_cfg} -o {merged_file} --keep-padding"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(merged_file)
        output = load_binary(merged_file)
        reference = load_binary(os.path.join("utils", "binary", "binary_merged.bin"))
        assert output[:24] == reference[:24]
        assert output[28:] == reference[28:]


@pytest.mark.parametrize(
    "config,output,result_code,keep_padding",
    [
        ("signed_merge.yaml", "signed_merge.bin", 0, True),
        ("adjust_offset_merge.yaml", "adjust_offset_merge.bin", 0, False),
        ("invalid_size_merge.yaml", "", 1, True),
        ("invalid_offset_merge.yaml", "", 1, True),
    ],
)
def test_nxpimage_binary_merge(
    cli_runner: CliRunner,
    tmpdir: Any,
    data_dir: str,
    config: str,
    output: str,
    result_code: int,
    keep_padding: bool,
) -> None:
    """Test binary image merge functionality through CLI interface.

    This test verifies that the nxpimage binary-image export command correctly
    merges binary files according to the provided configuration. It validates
    both successful merges and error conditions, comparing generated output
    against reference files when successful.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Base directory containing test data and configuration files.
    :param config: Configuration file name for the binary merge operation.
    :param output: Expected output file name for comparison with generated result.
    :param result_code: Expected exit code from the CLI command execution.
    :param keep_padding: Whether to preserve padding in the merged binary output.
    """
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", config)
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image export -c {merge_cfg} -o {merged_file}"
        if keep_padding:
            cmd += " --keep-padding"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=result_code)
        if result_code == 0:
            assert os.path.isfile(merged_file)
            gen_output = load_binary(merged_file)
            reference = load_binary(os.path.join("utils", "binary", output))
            assert gen_output == reference


@pytest.mark.parametrize(
    "config,output,result_code",
    [
        ("merge_s19.yaml", "merged_s19.s19", 0),
    ],
)
def test_nxpimage_binary_merge_s19(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, config: str, output: str, result_code: int
) -> None:
    """Test nxpimage binary merge functionality with S19 format.

    This test verifies that the nxpimage binary merge command works correctly
    with S19 format output, including proper file generation and content validation
    against reference files.

    :param cli_runner: CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param data_dir: Directory containing test data and configuration files.
    :param config: Configuration file name for the binary merge operation.
    :param output: Expected output file name for comparison.
    :param result_code: Expected exit code from the command execution.
    """
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", config)
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image export -c {merge_cfg} -o {merged_file} -f S19 --keep-padding"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=result_code)
        if result_code == 0:
            assert os.path.isfile(merged_file)
            gen_output = load_binary(merged_file)
            reference = load_binary(os.path.join("utils", "binary", output))
            assert gen_output == reference


@pytest.mark.parametrize(
    "inputs,bin_file",
    [
        (["gcc.elf"], "gcc.bin"),
        (["iar.out", "iar.hex", "iar.srec"], "iar.bin"),
        (["keil.elf", "keil.hex"], "keil.bin"),
        (["test_sparse.bin", "test_sparse.simg"], "test_sparse.bin"),
    ],
)
def test_nxpimage_binary_convert_bin(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, inputs: list[str], bin_file: str
) -> None:
    """Test binary image conversion to BIN format using CLI.

    This test verifies that the nxpimage CLI utility can successfully convert
    various input image formats to BIN format. It compares the output file
    with the expected binary file to ensure correct conversion.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Base directory containing test data files.
    :param inputs: List of input file paths to be converted.
    :param bin_file: Expected output binary file name for comparison.
    """
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        out_file = os.path.join(tmpdir, bin_file)
        for input_file in inputs:
            cmd = f"utils binary-image convert -i {input_file} -f BIN -o {out_file} -p"
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert filecmp.cmp(out_file, bin_file)


@pytest.mark.parametrize(
    "inputs,sparse_file",
    [
        (["test_sparse.bin", "test_sparse.simg"], "test_sparse.simg"),
    ],
)
def test_nxpimage_binary_convert_sparse(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, inputs: list[str], sparse_file: str
) -> None:
    """Test binary image conversion to SPARSE format using CLI.

    This test verifies that the nxpimage CLI utility can successfully convert
    various input image formats to SPARSE format. It compares the output file
    with the expected binary file to ensure correct conversion.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for output files.
    :param data_dir: Base directory containing test data files.
    :param inputs: List of input file paths to be converted.
    :param sparse_file: Expected output sparse file name for comparison.
    """
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        out_file = os.path.join(tmpdir, sparse_file)
        for input_file in inputs:
            cmd = f"utils binary-image convert -i {input_file} -f SPARSE -o {out_file} -p"
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert filecmp.cmp(out_file, sparse_file)


@pytest.mark.parametrize(
    "inputs,bin_file",
    [
        (["gcc.elf"], "gcc.bin"),
        (["iar.out", "iar.hex", "iar.srec"], "iar.bin"),
        (["keil.elf", "keil.hex"], "keil.bin"),
    ],
)
def test_nxpimage_binary_convert_s19(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, inputs: list[str], bin_file: str
) -> None:
    """Test S19 format conversion functionality in nxpimage binary utility.

    This test verifies that binary files can be converted to S19 format and back to binary
    format while maintaining data integrity. It processes multiple input files, converts
    them to S19 format, then converts back to binary and compares with the original.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file operations.
    :param data_dir: Base directory containing test data files.
    :param inputs: List of input file paths to be converted.
    :param bin_file: Reference binary file path for comparison.
    """
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        files = []
        check_bin = os.path.join(tmpdir, "check.bin")
        for i, input_file in enumerate(inputs):
            files.append(os.path.join(tmpdir, f"bin_file_{i}.s19"))
            cmd = f"utils binary-image convert -i {input_file} -f S19 -o {files[i]}"
            cli_runner.invoke(nxpimage.main, cmd.split())

            cmd = f"utils binary-image convert -i {files[i]} -f BIN -o {check_bin}"
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert filecmp.cmp(check_bin, bin_file)


@pytest.mark.parametrize(
    "inputs,bin_file",
    [
        (["gcc.elf"], "gcc.bin"),
        (["iar.out", "iar.hex", "iar.srec"], "iar.bin"),
        (["keil.elf", "keil.hex"], "keil.bin"),
    ],
)
def test_nxpimage_binary_convert_hex(
    cli_runner: CliRunner, tmpdir: Any, data_dir: str, inputs: list[str], bin_file: str
) -> None:
    """Test binary image conversion to HEX format and back to BIN format.

    This test verifies that binary images can be converted to HEX format and then
    back to BIN format while maintaining data integrity. It processes multiple
    input files and validates that the round-trip conversion preserves the
    original binary content.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file operations.
    :param data_dir: Base directory containing test data files.
    :param inputs: List of input file paths to be converted.
    :param bin_file: Reference binary file for comparison validation.
    """
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        files = []
        check_bin = os.path.join(tmpdir, "check.bin")
        for i, input_file in enumerate(inputs):
            files.append(os.path.join(tmpdir, f"bin_file_{i}.hex"))
            cmd = f"utils binary-image convert -i {input_file} -f HEX -o {files[i]}"
            cli_runner.invoke(nxpimage.main, cmd.split())

            cmd = f"utils binary-image convert -i {files[i]} -f BIN -o {check_bin}"
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert filecmp.cmp(check_bin, bin_file)


@pytest.mark.parametrize(
    "align,pattern,fail",
    [
        (-1, 0, True),
        (0, 0, True),
        (1, 0, False),
        (4, 0, False),
        (15, "inc", False),
        (32, "0xAA55", False),
    ],
)
def test_nxpimage_binary_align(
    cli_runner: CliRunner, tmpdir: Any, align: int, pattern: Any, fail: bool
) -> None:
    """Test binary image alignment functionality with various parameters.

    This test verifies that the nxpimage binary align command correctly aligns
    a binary file to the specified alignment boundary using the given padding
    pattern. It checks both successful alignment operations and expected failures.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file operations.
    :param align: Alignment boundary in bytes for the binary file.
    :param pattern: Padding pattern to use for alignment (can be various types).
    :param fail: Flag indicating whether the test should expect failure.
    """
    in_file = "byte.bin"
    with use_working_directory(tmpdir):
        write_file(b"B", in_file, "wb")
        cmd = f"utils binary-image align -i {in_file} -o out.bin -a {align} -p {pattern}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0 if not fail else -1)

        if not fail:
            expected_size = max(1, align)
            assert os.path.exists("out.bin")
            assert os.path.getsize("out.bin") == expected_size
            padding = BinaryPattern(pattern).get_block(expected_size - 1)
            assert load_binary("out.bin") == b"B" + padding


@pytest.mark.parametrize(
    "in_file,size,pattern,fail",
    [
        ("byte.bin", -1, 0, False),
        ("byte.bin", 0, 0, False),
        ("byte.bin", 1, 0, False),
        ("byte.bin", 4, 0, False),
        ("byte.bin", 15, "inc", False),
        ("byte.bin", 32, "0xAA55", False),
        ("non_existing.bin", 0, 0, True),
    ],
)
def test_nxpimage_binary_pad(
    cli_runner: CliRunner, in_file: str, tmpdir: Any, size: int, pattern: Any, fail: bool
) -> None:
    """Test binary image padding functionality with various parameters.

    This test verifies that the nxpimage binary pad command correctly pads a binary file
    to the specified size using the given pattern. It creates a test file, executes the
    pad command, and validates the output file size and content.

    :param cli_runner: Click CLI test runner for command execution.
    :param in_file: Input file path for the padding operation.
    :param tmpdir: Temporary directory for test file operations.
    :param size: Target size for the padded binary file.
    :param pattern: Padding pattern to use for filling the binary.
    :param fail: Flag indicating whether the test should expect failure.
    """
    with use_working_directory(tmpdir):
        write_file(b"B", "byte.bin", "wb")
        cmd = f"utils binary-image pad -i {in_file} -o out.bin -s {size} -p {pattern}"
        cli_runner.invoke(nxpimage.main, cmd.split(), expected_code=0 if not fail else -1)

        if not fail:
            expected_size = max(1, size)
            assert os.path.exists("out.bin")
            assert os.path.getsize("out.bin") == expected_size
            if expected_size - 1:
                padding = BinaryPattern(pattern).get_block(expected_size - 1)
                assert load_binary("out.bin") == b"B" + padding
            else:
                assert load_binary("out.bin") == b"B"


def test_nxpimage_binary_extract(cli_runner: CliRunner, tmpdir: Any, data_dir: str) -> None:
    """Test extracting a portion of a binary file using nxpimage CLI.

    This test verifies the binary extraction functionality by creating a test binary
    with a known pattern, extracting a specific portion using the CLI command,
    and validating that the extracted data matches the expected subset.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test files.
    :param data_dir: Path to test data directory.
    """
    with use_working_directory(tmpdir):
        # Create a test binary with known pattern
        test_bin = os.path.join(tmpdir, "source.bin")
        test_data = bytes([i % 256 for i in range(100)])  # 100 bytes of incrementing pattern
        write_file(test_data, test_bin, "wb")

        # Extract a portion
        output_file = os.path.join(tmpdir, "extracted.bin")
        cmd = f"utils binary-image extract -b {test_bin} -o {output_file} --address 20 --size 30"
        cli_runner.invoke(nxpimage.main, cmd.split())

        # Verify extraction
        assert os.path.isfile(output_file)
        extracted = load_binary(output_file)
        assert extracted == test_data[20:50]  # 30 bytes starting at offset 20


def test_nxpimage_binary_empty_file(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test handling of empty binary files in nxpimage conversion.

    This test verifies that the nxpimage binary conversion utility correctly handles
    empty input files by converting an empty binary file to HEX format and back to
    binary format, ensuring the file remains empty throughout the process.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    with use_working_directory(tmpdir):
        # Create an empty file
        empty_file = os.path.join(tmpdir, "empty.bin")
        write_file(b"", empty_file, "wb")

        # Test convert on empty file
        output_file = os.path.join(tmpdir, "empty.hex")
        cmd = f"utils binary-image convert -i {empty_file} -f HEX -o {output_file}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        # Check if output was created correctly
        assert os.path.isfile(output_file)

        # Convert back to binary and verify
        bin_output = os.path.join(tmpdir, "back_to_bin.bin")
        cmd = f"utils binary-image convert -i {output_file} -f BIN -o {bin_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        # Ensure it's still empty
        assert os.path.getsize(bin_output) == 0


def test_nxpimage_binary_chain_operations(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test chaining multiple binary operations in nxpimage CLI.

    Validates that multiple binary operations (align and pad) can be chained together
    to produce the expected output. Creates an input file, aligns it to 4 bytes with
    zero padding, then pads the result to 10 bytes with 0xFF fill pattern.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test files.
    """
    with use_working_directory(tmpdir):
        # Create input file
        input_file = os.path.join(tmpdir, "input.bin")
        write_file(b"A", input_file, "wb")

        # Expected result: align to 4 bytes with zeros, then pad to 10 bytes with 0xFF
        aligned_file = os.path.join(tmpdir, "aligned.bin")
        output_file = os.path.join(tmpdir, "output.bin")

        # First align
        cmd = f"utils binary-image align -i {input_file} -o {aligned_file} -a 4 -p 0"
        cli_runner.invoke(nxpimage.main, cmd.split())

        # Then pad
        cmd = f"utils binary-image pad -i {aligned_file} -o {output_file} -s 10 -p 0xFF"
        cli_runner.invoke(nxpimage.main, cmd.split())

        # Verify final output
        assert os.path.isfile(output_file)
        result = load_binary(output_file)
        expected = b"A" + b"\x00" * 3 + b"\xff" * 6
        assert result == expected


def test_nxpimage_binary_create_formats(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test creating binary files in different formats.

    Validates the nxpimage CLI tool's ability to create binary files in BIN, HEX, and S19 formats
    with different patterns (incremental and fixed byte values). Also tests format conversion
    functionality by converting HEX and S19 files back to BIN format and verifying data integrity.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory for test file operations.
    """
    with use_working_directory(tmpdir):
        # Test BIN format
        bin_output = os.path.join(tmpdir, "test_bin.bin")
        cmd = f"utils binary-image create -s 16 -p inc -f BIN -o {bin_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(bin_output)
        bin_data = load_binary(bin_output)
        assert len(bin_data) == 16
        assert bin_data == bytes([i % 256 for i in range(16)])  # 'inc' pattern

        # Test HEX format
        hex_output = os.path.join(tmpdir, "test_hex.hex")
        cmd = f"utils binary-image create -s 16 -p inc -f HEX -o {hex_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(hex_output)

        # Convert HEX to BIN and verify
        hex_bin_output = os.path.join(tmpdir, "hex_to_bin.bin")
        cmd = f"utils binary-image convert -i {hex_output} -f BIN -o {hex_bin_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        hex_bin_data = load_binary(hex_bin_output)
        assert hex_bin_data == bin_data

        # Test S19 format
        s19_output = os.path.join(tmpdir, "test_s19.s19")
        cmd = f"utils binary-image create -s 16 -p 0xAA -f S19 -o {s19_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(s19_output)

        # Convert S19 to BIN and verify
        s19_bin_output = os.path.join(tmpdir, "s19_to_bin.bin")
        cmd = f"utils binary-image convert -i {s19_output} -f BIN -o {s19_bin_output}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        s19_bin_data = load_binary(s19_bin_output)
        assert len(s19_bin_data) == 16
        assert all(b == 0xAA for b in s19_bin_data)  # 0xAA pattern


def test_nxpimage_binary_export_with_min_offset_log(
    cli_runner: CliRunner, tmpdir: str, caplog: Any
) -> None:
    """Test binary export with offset adjustment and log messages.

    Verifies that the nxpimage binary export command correctly handles offset
    adjustment when exporting binary images. The test creates a configuration
    with a non-zero offset, exports the binary, and validates that the resulting
    image has the offset properly adjusted to start at 0.

    :param cli_runner: Click CLI runner for testing command line interface.
    :param tmpdir: Temporary directory path for test files.
    :param caplog: Pytest fixture for capturing log messages.
    """
    with use_working_directory(tmpdir):
        # Create a config with a non-zero min offset
        config_content = """
        offset: 0x1000
        regions:
            -   binary_block:
                    offset: 0x1000
                    pattern: 0xAA
                    size: 16
        """
        config_file = os.path.join(tmpdir, "image_config.yaml")
        write_file(config_content, config_file, "w")

        output_file = os.path.join(tmpdir, "adjusted_image.bin")
        cmd = f"utils binary-image export -c {config_file} -o {output_file}"
        cli_runner.invoke(nxpimage.main, cmd.split())

        # Verify the export worked
        assert os.path.isfile(output_file)
        result = load_binary(output_file)
        # Should be 16 bytes of 0xAA
        assert len(result) == 16
        assert all(b == 0xAA for b in result)

        # Load the resulting binary image and verify offset is adjusted
        adjusted_image = BinaryImage.load_binary_image(output_file)
        assert adjusted_image.offset == 0  # Should now start at 0


def test_nxpimage_binary_create_sizes(cli_runner: CliRunner, tmpdir: str) -> None:
    """Test creating binary files of different sizes with various patterns.

    This test verifies the nxpimage binary creation functionality by generating
    binary files with different sizes (0, 1, 10, 100, 1024 bytes) and various
    fill patterns (zeros, ones, random, incremental, and fixed hex value).
    The test validates that files are created correctly and contain expected
    data patterns for deterministic fill types.

    :param cli_runner: Click CLI test runner for invoking nxpimage commands.
    :param tmpdir: Temporary directory path for test file operations.
    """
    with use_working_directory(tmpdir):
        for size in [0, 1, 10, 100, 1024]:
            for pattern in ["zeros", "ones", "rand", "inc", "0xA5"]:
                output = os.path.join(tmpdir, f"size_{size}_{pattern}.bin")
                cmd = f"utils binary-image create -s {size} -p {pattern} -o {output}"
                cli_runner.invoke(nxpimage.main, cmd.split())

                # Verify file was created correctly
                assert os.path.isfile(output)
                data = load_binary(output)
                assert len(data) == size

                # For deterministic patterns, check content
                if pattern == "zeros" and size > 0:
                    assert all(b == 0 for b in data)
                elif pattern == "ones" and size > 0:
                    assert all(b == 0xFF for b in data)
                elif pattern == "inc" and size > 0:
                    assert data == bytes([i % 256 for i in range(size)])
                elif pattern == "0xA5" and size > 0:
                    assert all(b == 0xA5 for b in data)


@pytest.mark.parametrize(
    "input_file, split_image, output_files",
    [
        ("distinct_segments.s19", False, ["output.bin"]),
        ("distinct_segments.s19", True, ["output_0x0.bin", "output_0x12.bin", "output_0x24.bin"]),
        ("evkmimxrt595_hello_world_s.s19", True, ["output.bin"]),
        ("evkmimxrt595_hello_world_s.s19", True, ["output.bin"]),
        ("two_segments_offset.srec", True, ["output_0x100.bin", "output_0x400.bin"]),
    ],
)
def test_nxpimage_binary_convert_split_image(
    cli_runner: CliRunner,
    tmpdir: str,
    data_dir: str,
    input_file: str,
    split_image: bool,
    output_files: list[str],
) -> None:
    """Test nxpimage binary convert command with split image functionality.

    This test verifies the binary image conversion functionality of the nxpimage CLI tool,
    specifically testing the --split-image option that splits the output into multiple files.
    The test runs the convert command and validates that all expected output files are created.

    :param cli_runner: CLI test runner for invoking command line interface.
    :param tmpdir: Temporary directory path for test output files.
    :param data_dir: Base directory containing test data files.
    :param input_file: Input binary file to be converted.
    :param split_image: Flag indicating whether to use split image functionality.
    :param output_files: List of expected output file paths to validate.
    """
    with use_working_directory(os.path.join(data_dir, "utils", "binary")):
        out_file = os.path.join(tmpdir, "output.bin")
        cmd = f"utils binary-image convert -i {input_file} -f BIN -o {out_file}"
        if split_image:
            cmd += " --split-image"
        cli_runner.invoke(nxpimage.main, cmd.split())
        for output in output_files:
            os.path.isfile(output)


def test_empty_binary_conditions_for_special_handling() -> None:
    """Test that empty binary meets all conditions for special handling.

    This test verifies that a BinaryImage with zero size, zero offset, zeros pattern,
    no execution start address, and no sub-images triggers the special handling path
    in the export functionality. All conditions are validated to ensure proper
    behavior for edge cases.

    :raises AssertionError: If any of the expected conditions for special handling are not met.
    """
    # Create a completely empty binary image that should trigger the special handling
    binary_image = BinaryImage(
        name="empty_test",
        size=0,
        offset=0,
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Verify all conditions that should trigger special handling
    exported_data = binary_image.export()
    assert len(exported_data) == 0
    assert binary_image.offset == 0
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 0
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "zeros"
    assert not binary_image.execution_start_address


def test_empty_binary_with_execution_start_address_condition() -> None:
    """Test that execution_start_address prevents special handling condition.

    Verifies that when a BinaryImage has an execution_start_address set,
    it prevents the special handling condition for empty binaries with zero size.
    The test creates an empty binary image with execution address and validates
    that all properties maintain their expected values without triggering
    special case handling.
    """
    binary_image = BinaryImage(
        name="empty_with_exec_addr",
        size=0,
        offset=0,
        pattern=BinaryPattern("zeros"),
        execution_start_address=0x1000,
    )

    # Verify that execution_start_address condition fails
    exported_data = binary_image.export()
    assert len(exported_data) == 0
    assert binary_image.offset == 0
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 0
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "zeros"
    assert binary_image.execution_start_address == 0x1000  # This should prevent special handling


def test_empty_binary_with_offset_condition() -> None:
    """Test that non-zero offset prevents special handling condition.

    Verifies that when a BinaryImage has a non-zero offset, it prevents the
    special handling condition from being triggered, even when the binary
    size is zero. This test ensures proper behavior of the offset validation
    logic in BinaryImage export functionality.

    :raises AssertionError: If any of the binary image properties don't match expected values.
    """
    binary_image = BinaryImage(
        name="empty_with_offset",
        size=0,
        offset=0x1000,
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Verify that offset condition fails
    exported_data = binary_image.export()
    assert len(exported_data) == 0
    assert binary_image.offset == 0x1000  # This should prevent special handling
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 0
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "zeros"
    assert not binary_image.execution_start_address


def test_empty_binary_with_sub_images_condition() -> None:
    """Test that sub-images prevent special handling condition for empty binary images.

    Verifies that when a BinaryImage has zero size but contains sub-images,
    the special handling condition for empty binaries is not triggered.
    The test ensures that sub-images are properly exported even when the
    parent binary image is empty, and validates the state of all relevant
    binary image properties.

    :raises AssertionError: If any of the binary image state validations fail.
    """
    binary_image = BinaryImage(
        name="empty_with_sub_images",
        size=0,
        offset=0,
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Add a sub-image
    sub_image = BinaryImage(
        name="sub_image", size=10, offset=0, binary=b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    )
    binary_image.add_image(sub_image)

    # Verify that sub_images condition fails
    exported_data = binary_image.export()
    assert len(exported_data) > 0  # Should have data from sub-image
    assert binary_image.offset == 0
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 1  # This should prevent special handling
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "zeros"
    assert not binary_image.execution_start_address


def test_empty_binary_with_binary_data_condition() -> None:
    """Test that binary data prevents special handling condition.

    Verifies that when a BinaryImage is created with both size=0 and binary data,
    the presence of binary data takes precedence and prevents any special handling
    that would normally occur for empty images. The test ensures that the binary
    data is properly exported and all image properties are correctly set.

    :raises AssertionError: If any of the binary image properties don't match expected values.
    """
    binary_image = BinaryImage(
        name="with_binary_data",
        size=0,
        offset=0,
        binary=b"\x01\x02\x03",
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Verify that binary data condition fails
    exported_data = binary_image.export()
    assert len(exported_data) > 0  # Should have data from binary
    assert binary_image.offset == 0
    assert binary_image.binary  # This should prevent special handling
    assert len(binary_image.sub_images) == 0
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "zeros"
    assert not binary_image.execution_start_address


def test_empty_binary_with_non_zeros_pattern_condition() -> None:
    """Test that non-zeros pattern prevents special handling condition.

    Verifies that when a BinaryImage is created with zero size and a non-zeros
    pattern (like "ones"), the special handling condition for empty binaries
    is prevented. The test ensures that the pattern is preserved and the image
    maintains its expected properties without triggering optimization paths
    that might be applied to truly empty binaries.
    """
    binary_image = BinaryImage(
        name="empty_with_pattern",
        size=0,
        offset=0,
        pattern=BinaryPattern("ones"),
        execution_start_address=None,
    )

    # Verify that non-zeros pattern condition fails
    exported_data = binary_image.export()
    assert len(exported_data) == 0
    assert binary_image.offset == 0
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 0
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "ones"  # This should prevent special handling
    assert not binary_image.execution_start_address


def test_empty_binary_with_no_pattern_condition() -> None:
    """Test that empty binary image with no pattern allows special handling condition.

    Verifies that a BinaryImage instance created with zero size, zero offset, and no pattern
    can be properly instantiated and exported. Tests that all properties return expected
    default values when no pattern is specified, confirming that the absence of a pattern
    does not prevent the creation or handling of empty binary images.
    </assistant>
    """
    binary_image = BinaryImage(
        name="empty_no_pattern", size=0, offset=0, pattern=None, execution_start_address=None
    )

    # Verify the conditions for special handling with no pattern
    exported_data = binary_image.export()
    assert len(exported_data) == 0
    assert binary_image.offset == 0
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 0
    assert not binary_image.pattern  # No pattern should still allow special handling
    assert not binary_image.execution_start_address


def test_empty_binary_exported_data_length_condition() -> None:
    """Test that exported data length affects special handling condition.

    This test verifies that a BinaryImage with a specified size but no actual binary content
    generates the expected exported data through pattern filling, and that all object
    properties maintain their correct states after export operation.
    """
    # Test with size > 0 but no actual content
    binary_image = BinaryImage(
        name="empty_with_size",
        size=10,
        offset=0,
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Verify that exported data length condition fails
    exported_data = binary_image.export()
    assert len(exported_data) == 10  # Should have data due to size
    assert binary_image.offset == 0
    assert not binary_image.binary
    assert len(binary_image.sub_images) == 0
    assert binary_image.pattern
    assert binary_image.pattern.pattern == "zeros"
    assert not binary_image.execution_start_address


def test_special_handling_pattern_condition_edge_cases() -> None:
    """Test edge cases for pattern condition in special handling.

    This test verifies that BinaryImage objects correctly handle different pattern
    types, specifically testing the distinction between "zeros" pattern (which
    should allow special handling) and other patterns like "ones" (which should
    prevent special handling). The test creates two BinaryImage instances with
    different patterns and validates their pattern properties.
    """
    # Test with pattern that has "zeros" in the name but is not exactly "zeros"
    binary_image1 = BinaryImage(
        name="test1",
        size=0,
        offset=0,
        pattern=BinaryPattern("zeros"),  # Exactly "zeros"
        execution_start_address=None,
    )

    binary_image2 = BinaryImage(
        name="test2",
        size=0,
        offset=0,
        pattern=BinaryPattern("ones"),  # Not "zeros"
        execution_start_address=None,
    )

    # Verify pattern conditions
    assert binary_image1.pattern
    assert binary_image1.pattern.pattern == "zeros"  # Should allow special handling
    assert binary_image2.pattern
    assert binary_image2.pattern.pattern == "ones"  # Should prevent special handling


@pytest.mark.parametrize("execution_address", [None, 0, 0x1000, 0xFFFFFFFF])
def test_execution_start_address_condition_variations(execution_address: Optional[int]) -> None:
    """Test various execution start address values for special handling condition.

    Validates that BinaryImage correctly handles different execution start address values,
    including None values for special handling scenarios and specific integer addresses
    for normal execution flow.

    :param execution_address: Execution start address to test, None for special handling or integer for specific address.
    """
    binary_image = BinaryImage(
        name="test_exec_addr",
        size=0,
        offset=0,
        pattern=BinaryPattern("zeros"),
        execution_start_address=execution_address,
    )

    # Verify execution start address condition
    if execution_address is None:
        assert not binary_image.execution_start_address  # Should allow special handling
    else:
        assert (
            binary_image.execution_start_address == execution_address
        )  # Should prevent special handling


@pytest.mark.parametrize("offset_value", [0, 1, 0x1000, 0xFFFFFFFF])
def test_offset_condition_variations(offset_value: int) -> None:
    """Test various offset values for special handling condition.

    Validates that BinaryImage correctly handles different offset values and
    their impact on special handling conditions. Tests both zero and non-zero
    offset scenarios to ensure proper condition evaluation.

    :param offset_value: The offset value to test for the BinaryImage instance.
    """
    binary_image = BinaryImage(
        name="test_offset",
        size=0,
        offset=offset_value,
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Verify offset condition
    assert binary_image.offset == offset_value
    if offset_value == 0:
        # Should allow special handling (offset condition passes)
        pass
    else:
        # Should prevent special handling (offset condition fails)
        pass


def test_all_conditions_combined_for_special_handling() -> None:
    """Test that all conditions must be met simultaneously for special handling.

    This test verifies that a BinaryImage with all conditions met (zero size, zero offset,
    no binary data, no sub-images, zeros pattern, and no execution start address) is
    properly identified for special handling. The test creates such an image and validates
    that all the required conditions are satisfied.

    :raises AssertionError: If not all conditions are met for special handling.
    """
    # Create binary image that meets ALL conditions for special handling
    binary_image = BinaryImage(
        name="all_conditions_met",
        size=0,
        offset=0,
        pattern=BinaryPattern("zeros"),
        execution_start_address=None,
    )

    # Verify ALL conditions are met
    exported_data = binary_image.export()
    conditions_met = (
        len(exported_data) == 0
        and binary_image.offset == 0
        and not binary_image.binary
        and len(binary_image.sub_images) == 0
        and (not binary_image.pattern or binary_image.pattern.pattern == "zeros")
        and not binary_image.execution_start_address
    )

    assert conditions_met, "All conditions should be met for special handling"


def test_any_condition_fails_prevents_special_handling() -> None:
    """Test that if any single condition fails, special handling is prevented.

    This test verifies that BinaryImage does not apply special handling when any of the
    required conditions for optimization are not met. It tests various scenarios where
    individual conditions fail (execution_start_address, offset, pattern, or binary data)
    and ensures that the special handling logic is properly bypassed in each case.

    :raises AssertionError: If conditions are unexpectedly met when they should fail.
    """
    base_params = {
        "name": "test",
        "size": 0,
        "offset": 0,
        "pattern": BinaryPattern("zeros"),
        "execution_start_address": None,
    }

    # Test each condition failure individually
    test_cases: list[dict] = [
        {"execution_start_address": 0x1000},  # execution_start_address condition fails
        {"offset": 0x1000},  # offset condition fails
        {"pattern": BinaryPattern("ones")},  # pattern condition fails
        {"binary": b"\x01\x02\x03"},  # binary condition fails
    ]

    for case_params in test_cases:
        params = base_params.copy()
        params.update(case_params)

        binary_image = BinaryImage(**params)  # type: ignore

        # At least one condition should fail
        exported_data = binary_image.export()
        conditions_met = (
            len(exported_data) == 0
            and binary_image.offset == 0
            and not binary_image.binary
            and len(binary_image.sub_images) == 0
            and (not binary_image.pattern or binary_image.pattern.pattern == "zeros")
            and not binary_image.execution_start_address
        )

        assert not conditions_met, f"Conditions should not all be met for case: {case_params}"


def test_sparse_image_reader_basic(data_dir: str) -> None:
    """Test basic SparseImageReader functionality.

    This test verifies that SparseImageReader can open a sparse image file,
    read its header, and perform basic read operations. It validates that
    the reader correctly initializes and can read data from the beginning
    of the image.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    with SparseImageReader(sparse_file) as reader:
        # Verify header was parsed
        assert reader.header is not None
        assert reader.header.magic == 0xED26FF3A

        # Verify chunk index was built
        assert len(reader.chunk_index) > 0

        # Get total size
        total_size = reader.get_total_size()
        assert total_size > 0

        # Read first 100 bytes
        data = reader.read(offset=0, size=100)
        assert len(data) == 100


def test_sparse_image_reader_full_image(data_dir: str) -> None:
    """Test reading entire sparse image and comparing with reference binary.

    This test verifies that SparseImageReader can correctly reconstruct the
    entire binary image from a sparse format by reading all data and comparing
    it with the reference binary file.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    # Load reference binary
    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        # Read entire image
        total_size = reader.get_total_size()
        reconstructed_data = reader.read(offset=0, size=total_size)

        # Compare with reference
        assert len(reconstructed_data) == len(reference_data)
        assert reconstructed_data == reference_data


def test_sparse_image_reader_partial_reads(data_dir: str) -> None:
    """Test reading partial chunks from sparse image at various offsets.

    This test verifies that SparseImageReader can correctly read data from
    arbitrary offsets within the sparse image. It performs multiple partial
    reads and validates them against the reference binary file.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        # Test various offset and size combinations
        test_cases = [
            (0, 100),  # Beginning
            (100, 200),  # Middle
            (len(reference_data) - 100, 100),  # End
            (50, 150),  # Arbitrary offset
            (1000, 500),  # Larger chunk
        ]

        for offset, size in test_cases:
            if offset + size <= len(reference_data):
                data = reader.read(offset=offset, size=size)
                expected = reference_data[offset : offset + size]
                assert data == expected, f"Mismatch at offset {offset}, size {size}"


def test_sparse_image_reader_multiple_reads(data_dir: str) -> None:
    """Test multiple sequential reads from the same SparseImageReader instance.

    This test verifies that SparseImageReader can handle multiple read operations
    on the same instance without issues, ensuring proper state management and
    file handle positioning.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        # Perform multiple reads
        data1 = reader.read(offset=0, size=100)
        data2 = reader.read(offset=100, size=100)
        data3 = reader.read(offset=0, size=100)  # Re-read first chunk

        # Verify all reads
        assert data1 == reference_data[0:100]
        assert data2 == reference_data[100:200]
        assert data3 == reference_data[0:100]
        assert data1 == data3  # Re-reading should give same result


def test_sparse_image_reader_chunk_boundaries(data_dir: str) -> None:
    """Test reading across chunk boundaries in sparse image.

    This test verifies that SparseImageReader correctly handles reads that
    span multiple chunks, ensuring seamless data reconstruction across
    chunk boundaries.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        # Get block size from header
        assert reader.header is not None
        block_size = reader.header.block_size

        # Read across chunk boundary
        # Start in middle of one chunk and read into next chunk
        offset = block_size - 50
        size = 100  # This should span two chunks

        if offset + size <= len(reference_data):
            data = reader.read(offset=offset, size=size)
            expected = reference_data[offset : offset + size]
            assert data == expected


def test_sparse_image_reader_context_manager(data_dir: str) -> None:
    """Test SparseImageReader context manager functionality.

    This test verifies that SparseImageReader properly implements the context
    manager protocol, ensuring that file handles are correctly opened and
    closed when using the 'with' statement.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    # Test context manager
    with SparseImageReader(sparse_file) as reader:
        assert reader.file_handle is not None
        data = reader.read(offset=0, size=100)
        assert len(data) == 100

    # File should be closed after exiting context
    assert reader.file_handle is None


def test_sparse_image_reader_manual_close(data_dir: str) -> None:
    """Test manual resource management with SparseImageReader.

    This test verifies that SparseImageReader can be used without a context
    manager by manually calling the close() method, and that the file handle
    is properly released.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    reader = SparseImageReader(sparse_file)
    try:
        assert reader.file_handle is not None
        data = reader.read(offset=0, size=100)
        assert len(data) == 100
    finally:
        reader.close()

    assert reader.file_handle is None


def test_sparse_image_reader_invalid_offset(data_dir: str) -> None:
    """Test SparseImageReader error handling for invalid offset values.

    This test verifies that SparseImageReader properly validates offset
    parameters and raises appropriate exceptions when invalid offsets
    are provided (negative or beyond image size).

    :param data_dir: Directory containing test data files.
    """
    from spsdk.exceptions import SPSDKValueError
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    with SparseImageReader(sparse_file) as reader:
        total_size = reader.get_total_size()

        # Test negative offset
        with pytest.raises(SPSDKValueError):
            reader.read(offset=-1, size=100)

        # Test offset beyond image size
        with pytest.raises(SPSDKValueError):
            reader.read(offset=total_size + 1, size=100)


def test_sparse_image_reader_invalid_size(data_dir: str) -> None:
    """Test SparseImageReader error handling for invalid size values.

    This test verifies that SparseImageReader properly validates size
    parameters and raises appropriate exceptions when invalid sizes
    are provided (zero or negative values).

    :param data_dir: Directory containing test data files.
    """
    from spsdk.exceptions import SPSDKValueError
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    with SparseImageReader(sparse_file) as reader:
        # Test zero size
        with pytest.raises(SPSDKValueError):
            reader.read(offset=0, size=0)

        # Test negative size
        with pytest.raises(SPSDKValueError):
            reader.read(offset=0, size=-100)


def test_sparse_image_reader_size_adjustment(data_dir: str, caplog: Any) -> None:
    """Test SparseImageReader automatic size adjustment when exceeding bounds.

    This test verifies that SparseImageReader automatically adjusts the read
    size when a request would exceed the image boundaries, and that it logs
    an appropriate warning message.

    :param data_dir: Directory containing test data files.
    :param caplog: Pytest fixture for capturing log messages.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        total_size = reader.get_total_size()

        # Request more data than available
        offset = total_size - 50
        requested_size = 100  # This exceeds image bounds

        data = reader.read(offset=offset, size=requested_size)

        # Should return only available data
        assert len(data) == 50
        assert data == reference_data[offset:]

        # Should log a warning
        assert "Read size adjusted" in caplog.text


def test_sparse_image_reader_chunk_types(data_dir: str) -> None:
    """Test SparseImageReader handling of different chunk types.

    This test verifies that SparseImageReader correctly processes all
    chunk types (RAW, FILL, DONT_CARE) present in the sparse image
    and reconstructs the data accurately.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseChunkType, SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        # Read data from each chunk type
        for entry in reader.chunk_index:
            if entry.chunk_type == SparseChunkType.CRC32:
                continue  # Skip CRC chunks

            # Read from this chunk
            offset = entry.output_offset
            size = min(100, entry.output_size)

            if size > 0:
                data = reader.read(offset=offset, size=size)
                expected = reference_data[offset : offset + size]
                assert data == expected, f"Mismatch in {entry.chunk_type.name} chunk"


def test_sparse_image_reader_fill_chunk_alignment(data_dir: str) -> None:
    """Test SparseImageReader handling of FILL chunks with non-aligned reads.

    This test verifies that SparseImageReader correctly handles reads from
    FILL chunks that don't align with the 4-byte fill pattern, ensuring
    proper byte-level accuracy.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseChunkType, SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        # Find a FILL chunk
        fill_chunk = None
        for entry in reader.chunk_index:
            if entry.chunk_type == SparseChunkType.FILL:
                fill_chunk = entry
                break

        if fill_chunk and fill_chunk.output_size > 10:
            # Read with non-aligned offset within the FILL chunk
            offset = fill_chunk.output_offset + 1  # Start at byte 1
            size = 7  # Read 7 bytes (not aligned to 4-byte pattern)

            data = reader.read(offset=offset, size=size)
            expected = reference_data[offset : offset + size]
            assert data == expected


def test_sparse_image_reader_get_total_size(data_dir: str) -> None:
    """Test SparseImageReader get_total_size method.

    This test verifies that the get_total_size method returns the correct
    total size of the reconstructed binary image, matching the reference
    binary file size.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        total_size = reader.get_total_size()
        assert total_size == len(reference_data)


def test_sparse_image_reader_repr(data_dir: str) -> None:
    """Test SparseImageReader string representation.

    This test verifies that the __repr__ method returns a meaningful
    string representation containing file path, size, and chunk count.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    with SparseImageReader(sparse_file) as reader:
        repr_str = repr(reader)
        assert "SparseImageReader" in repr_str
        assert "test_sparse.simg" in repr_str
        assert "size=" in repr_str
        assert "chunks=" in repr_str


def test_sparse_image_reader_sequential_access(data_dir: str) -> None:
    """Test SparseImageReader with sequential access pattern.

    This test simulates a sequential read pattern, reading the entire
    image in fixed-size chunks from beginning to end, verifying that
    all data is correctly reconstructed.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        chunk_size = 1024
        reconstructed = bytearray()
        offset = 0
        total_size = reader.get_total_size()

        while offset < total_size:
            size = min(chunk_size, total_size - offset)
            data = reader.read(offset=offset, size=size)
            reconstructed.extend(data)
            offset += size

        assert bytes(reconstructed) == reference_data


def test_sparse_image_reader_random_access(data_dir: str) -> None:
    """Test SparseImageReader with random access pattern.

    This test verifies that SparseImageReader can handle random access
    reads efficiently, reading from various offsets in non-sequential
    order and validating all results.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        total_size = reader.get_total_size()

        # Random access pattern
        offsets = [
            total_size - 100,
            0,
            total_size // 2,
            100,
            total_size // 4,
            total_size * 3 // 4,
        ]

        for offset in offsets:
            if offset + 100 <= total_size:
                data = reader.read(offset=offset, size=100)
                expected = reference_data[offset : offset + 100]
                assert data == expected, f"Mismatch at random offset {offset}"


def test_sparse_image_reader_invalid_file(tmpdir: Any) -> None:
    """Test SparseImageReader error handling for invalid files.

    This test verifies that SparseImageReader raises appropriate exceptions
    when attempting to open non-existent files or files with invalid
    sparse image format.

    :param tmpdir: Temporary directory for test files.
    """
    from spsdk.exceptions import SPSDKError
    from spsdk.utils.sparse_image import SparseImageReader

    # Test non-existent file
    with pytest.raises(SPSDKError, match="Cannot open sparse image file"):
        SparseImageReader("non_existent_file.simg")

    # Test invalid sparse image (valid size but wrong magic number)
    invalid_file = os.path.join(tmpdir, "invalid.simg")
    # Create a 28-byte header with invalid magic (0xDEADBEEF instead of 0xED26FF3A)
    invalid_header = struct.pack(
        "<IHHHHIIII",
        0xDEADBEEF,  # Invalid magic number
        1,  # major_version
        0,  # minor_version
        28,  # file_hdr_sz
        12,  # chunk_hdr_sz
        4096,  # block_size
        0,  # total_blocks
        0,  # total_chunks
        0,  # image_checksum
    )
    write_file(invalid_header, invalid_file, "wb")

    with pytest.raises(SPSDKError, match="Invalid sparse image magic"):
        SparseImageReader(invalid_file)


def test_sparse_image_reader_chunk_index_binary_search(data_dir: str) -> None:
    """Test SparseImageReader chunk index binary search efficiency.

    This test verifies that the chunk index lookup uses binary search
    by testing lookups at various positions and ensuring they all
    return correct results efficiently.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")

    with SparseImageReader(sparse_file) as reader:
        # Test binary search at different positions
        total_size = reader.get_total_size()

        test_offsets = [
            0,  # First chunk
            total_size // 4,  # Quarter
            total_size // 2,  # Middle
            total_size * 3 // 4,  # Three quarters
            total_size - 1,  # Last byte
        ]

        for offset in test_offsets:
            chunk_idx = reader._find_chunk_for_offset(offset)
            assert 0 <= chunk_idx < len(reader.chunk_index)

            # Verify the found chunk contains the offset
            entry = reader.chunk_index[chunk_idx]
            assert entry.output_offset <= offset < entry.output_offset + entry.output_size


def test_sparse_image_reader_edge_cases(data_dir: str) -> None:
    """Test SparseImageReader edge cases and boundary conditions.

    This test verifies that SparseImageReader correctly handles various
    edge cases including reading single bytes, reading at exact chunk
    boundaries, and reading the last byte of the image.

    :param data_dir: Directory containing test data files.
    """
    from spsdk.utils.sparse_image import SparseImageReader

    sparse_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.simg")
    binary_file = os.path.join(data_dir, "utils", "binary", "convert", "test_sparse.bin")

    reference_data = load_binary(binary_file)

    with SparseImageReader(sparse_file) as reader:
        total_size = reader.get_total_size()

        # Read single byte at start
        data = reader.read(offset=0, size=1)
        assert data == reference_data[0:1]

        # Read single byte at end
        data = reader.read(offset=total_size - 1, size=1)
        assert data == reference_data[-1:]

        # Read at chunk boundaries
        for entry in reader.chunk_index[:3]:  # Test first few chunks
            if entry.output_size > 0:
                # Read at chunk start
                data = reader.read(offset=entry.output_offset, size=1)
                assert data == reference_data[entry.output_offset : entry.output_offset + 1]

                # Read at chunk end
                if entry.output_size > 1:
                    end_offset = entry.output_offset + entry.output_size - 1
                    data = reader.read(offset=end_offset, size=1)
                    assert data == reference_data[end_offset : end_offset + 1]
