#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""

import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import (
    BinaryPattern,
    load_binary,
    load_configuration,
    use_working_directory,
    write_file,
)


def test_nxpimage_binary_template(tmpdir):
    runner = CliRunner()
    template_name = os.path.join(tmpdir, "binary_merge.yaml")
    cmd = f"utils binary-image get-template --output {template_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(template_name)
    load_configuration(template_name)


def test_nxpimage_binary_merge_with_random(tmpdir, data_dir):
    runner = CliRunner()
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", "binary_merge.yaml")
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image merge -c {merge_cfg} -o {merged_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(merged_file)
        output = load_binary(merged_file)
        reference = load_binary(os.path.join("utils", "binary", "binary_merged.bin"))
        assert output[:24] == reference[:24]
        assert output[28:] == reference[28:]


@pytest.mark.parametrize(
    "config,output,result_code",
    [
        ("signed_merge.yaml", "signed_merge.bin", 0),
        ("invalid_size_merge.yaml", "", 1),
        ("invalid_offset_merge.yaml", "", 1),
    ],
)
def test_nxpimage_binary_merge(tmpdir, data_dir, config, output, result_code):
    runner = CliRunner()
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", config)
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image merge -c {merge_cfg} -o {merged_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == result_code
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
def test_nxpimage_binary_convert_bin(tmpdir, data_dir, inputs, bin_file):
    runner = CliRunner()
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        out_file = os.path.join(tmpdir, bin_file)
        for input_file in inputs:
            cmd = f"utils binary-image convert -i {input_file} -f BIN -o {out_file}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0
            assert filecmp.cmp(out_file, bin_file)


@pytest.mark.parametrize(
    "inputs,bin_file",
    [
        (["gcc.elf"], "gcc.bin"),
        (["iar.out", "iar.hex", "iar.srec"], "iar.bin"),
        (["keil.elf", "keil.hex"], "keil.bin"),
    ],
)
def test_nxpimage_binary_convert_s19(tmpdir, data_dir, inputs, bin_file):
    runner = CliRunner()
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        files = []
        check_bin = os.path.join(tmpdir, "check.bin")
        for i, input_file in enumerate(inputs):
            files.append(os.path.join(tmpdir, f"bin_file_{i}.s19"))
            cmd = f"utils binary-image convert -i {input_file} -f S19 -o {files[i]}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0

            cmd = f"utils binary-image convert -i {files[i]} -f BIN -o {check_bin}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0
            assert filecmp.cmp(check_bin, bin_file)


@pytest.mark.parametrize(
    "inputs,bin_file",
    [
        (["gcc.elf"], "gcc.bin"),
        (["iar.out", "iar.hex", "iar.srec"], "iar.bin"),
        (["keil.elf", "keil.hex"], "keil.bin"),
    ],
)
def test_nxpimage_binary_convert_hex(tmpdir, data_dir, inputs, bin_file):
    runner = CliRunner()
    with use_working_directory(os.path.join(data_dir, "utils", "binary", "convert")):
        files = []
        check_bin = os.path.join(tmpdir, "check.bin")
        for i, input_file in enumerate(inputs):
            files.append(os.path.join(tmpdir, f"bin_file_{i}.hex"))
            cmd = f"utils binary-image convert -i {input_file} -f HEX -o {files[i]}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0

            cmd = f"utils binary-image convert -i {files[i]} -f BIN -o {check_bin}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0
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
def test_nxpimage_binary_align(tmpdir, align, pattern, fail):
    runner = CliRunner()
    in_file = "byte.bin"
    with use_working_directory(tmpdir):
        write_file(b"B", in_file, "wb")
        cmd = f"utils binary-image align -i {in_file} -o out.bin -a {align} -p {pattern}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code in [0] if not fail else [1, 2]

        if not fail:
            expected_size = max(1, align)
            assert os.path.exists("out.bin")
            assert os.path.getsize("out.bin") == expected_size
            padding = BinaryPattern(pattern).get_block(expected_size - 1)
            assert load_binary("out.bin") == b"B" + padding


@pytest.mark.parametrize(
    "size,pattern,fail",
    [
        (-1, 0, True),
        (0, 0, False),
        (1, 0, False),
        (4, 0, False),
        (15, "inc", False),
        (32, "0xAA55", False),
    ],
)
def test_nxpimage_binary_pad(tmpdir, size, pattern, fail):
    runner = CliRunner()
    in_file = "byte.bin"
    with use_working_directory(tmpdir):
        write_file(b"B", in_file, "wb")
        cmd = f"utils binary-image pad -i {in_file} -o out.bin -s {size} -p {pattern}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code in [0] if not fail else [1, 2]

        if not fail:
            expected_size = max(1, size)
            assert os.path.exists("out.bin")
            assert os.path.getsize("out.bin") == expected_size
            if expected_size - 1:
                padding = BinaryPattern(pattern).get_block(expected_size - 1)
                assert load_binary("out.bin") == b"B" + padding
            else:
                assert load_binary("out.bin") == b"B"
