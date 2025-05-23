#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""

import filecmp
import os

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


def test_nxpimage_binary_template(cli_runner: CliRunner, tmpdir):
    template_name = os.path.join(tmpdir, "binary_merge.yaml")
    cmd = f"utils binary-image get-template --output {template_name}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(template_name)
    load_configuration(template_name)


def test_nxpimage_binary_merge_with_random(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", "binary_merge.yaml")
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image export -c {merge_cfg} -o {merged_file}"
        cli_runner.invoke(nxpimage.main, cmd.split())
        assert os.path.isfile(merged_file)
        output = load_binary(merged_file)
        reference = load_binary(os.path.join("utils", "binary", "binary_merged.bin"))
        assert output[:24] == reference[:24]
        assert output[28:] == reference[28:]


@pytest.mark.parametrize(
    "config,output,result_code,adjust_offsets",
    [
        ("signed_merge.yaml", "signed_merge.bin", 0, False),
        ("adjust_offset_merge.yaml", "adjust_offset_merge.bin", 0, True),
        ("invalid_size_merge.yaml", "", 1, False),
        ("invalid_offset_merge.yaml", "", 1, False),
    ],
)
def test_nxpimage_binary_merge(
    cli_runner: CliRunner, tmpdir, data_dir, config, output, result_code, adjust_offsets
):
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", config)
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image export -c {merge_cfg} -o {merged_file}"
        if adjust_offsets:
            cmd += " --adjust-offsets"
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
    cli_runner: CliRunner, tmpdir, data_dir, config, output, result_code
):
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", config)
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image export -c {merge_cfg} -o {merged_file} -f S19"
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
    ],
)
def test_nxpimage_binary_convert_bin(cli_runner: CliRunner, tmpdir, data_dir, inputs, bin_file):
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        out_file = os.path.join(tmpdir, bin_file)
        for input_file in inputs:
            cmd = f"utils binary-image convert -i {input_file} -f BIN -o {out_file}"
            cli_runner.invoke(nxpimage.main, cmd.split())
            assert filecmp.cmp(out_file, bin_file)


@pytest.mark.parametrize(
    "inputs,bin_file",
    [
        (["gcc.elf"], "gcc.bin"),
        (["iar.out", "iar.hex", "iar.srec"], "iar.bin"),
        (["keil.elf", "keil.hex"], "keil.bin"),
    ],
)
def test_nxpimage_binary_convert_s19(cli_runner: CliRunner, tmpdir, data_dir, inputs, bin_file):
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
def test_nxpimage_binary_convert_hex(cli_runner: CliRunner, tmpdir, data_dir, inputs, bin_file):
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
def test_nxpimage_binary_align(cli_runner: CliRunner, tmpdir, align, pattern, fail):
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
def test_nxpimage_binary_pad(cli_runner: CliRunner, in_file, tmpdir, size, pattern, fail):
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


def test_nxpimage_binary_extract(cli_runner: CliRunner, tmpdir, data_dir):
    """Test extracting a portion of a binary file."""
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


def test_nxpimage_binary_empty_file(cli_runner: CliRunner, tmpdir):
    """Test handling of empty files."""
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


def test_nxpimage_binary_chain_operations(cli_runner: CliRunner, tmpdir):
    """Test chaining multiple binary operations."""
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


def test_nxpimage_binary_create_formats(cli_runner: CliRunner, tmpdir):
    """Test creating binary files in different formats."""
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


def test_nxpimage_binary_export_with_min_offset_log(cli_runner: CliRunner, tmpdir, caplog):
    """Test binary export with offset adjustment and log messages."""
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

        # Export with adjust_offsets
        output_file = os.path.join(tmpdir, "adjusted_image.bin")

        cmd = f"utils binary-image export -c {config_file} -o {output_file} --adjust-offsets"
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


def test_nxpimage_binary_create_sizes(cli_runner: CliRunner, tmpdir):
    """Test creating binary files of different sizes with various patterns."""
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
