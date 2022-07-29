#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""

import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.apps.utils.utils import load_configuration
from spsdk.utils.misc import load_binary, use_working_directory


def test_nxpimage_binary_template(tmpdir):
    runner = CliRunner()
    template_name = os.path.join(tmpdir, "binary_merge.yaml")
    cmd = f"utils binary-image get-template {template_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(template_name)
    load_configuration(template_name)


def test_nxpimage_binary_merge(tmpdir, data_dir):
    runner = CliRunner()
    with use_working_directory(data_dir):
        merge_cfg = os.path.join("utils", "binary", "binary_merge.yaml")
        merged_file = os.path.join(tmpdir, "merged.bin")
        cmd = f"utils binary-image merge -c {merge_cfg} {merged_file}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(merged_file)
        output = load_binary(merged_file)
        reference = load_binary(os.path.join("utils", "binary", "binary_merged.bin"))
        assert output[:24] == reference[:24]
        assert output[28:] == reference[28:]


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
            cmd = f"utils binary-image convert -i {input_file} -f BIN {out_file}"
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
            cmd = f"utils binary-image convert -i {input_file} -f S19 {files[i]}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0

            cmd = f"utils binary-image convert -i {files[i]} -f BIN {check_bin}"
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
            cmd = f"utils binary-image convert -i {input_file} -f HEX {files[i]}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0

            cmd = f"utils binary-image convert -i {files[i]} -f BIN {check_bin}"
            result = runner.invoke(nxpimage.main, cmd.split())
            assert result.exit_code == 0
            assert filecmp.cmp(check_bin, bin_file)
