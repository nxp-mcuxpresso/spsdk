#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test AHAB part of nxpimage app."""
import filecmp
import os

import pytest

from spsdk.apps import nxpimage
from spsdk.utils.misc import Endianness, use_working_directory
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "in_file,out_file,command,reverse",
    [
        ("inc_16.bin", "inc_16.txt", "bin2hex", False),
        ("inc_16.bin", "inc_16_r.txt", "bin2hex", True),
        ("inc_16_r.bin", "inc_16.txt", "bin2hex", True),
        ("inc_16.txt", "inc_16.bin", "hex2bin", False),
        ("inc_16.txt", "inc_16_r.bin", "hex2bin", True),
        ("inc_16_r.txt", "inc_16.bin", "hex2bin", True),
    ],
)
def test_nxpimage_convert_hexbin(
    cli_runner: CliRunner, tmpdir, data_dir, in_file, out_file, command, reverse
):
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/hexbin/{in_file}"
        correct_output = f"{data_dir}/utils/convert/hexbin/{out_file}"
        output = f"{tmpdir}/{out_file}"
        cmd = ["utils", "convert", command, "-i", input_file]
        if reverse:
            cmd.append("-r")
        cmd.extend(["-o", output])
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(output)
        assert filecmp.cmp(output, correct_output, shallow=False)


@pytest.mark.parametrize("in_file", [("inc_16.bin"), ("inc_16_invalid.hex")])
def test_nxpimage_convert_hexbin_invalid(cli_runner: CliRunner, tmpdir, data_dir, in_file):
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/hexbin/{in_file}"
        output = f"{tmpdir}/test.bin"
        cmd = ["utils", "convert", "hex2bin", "-i", input_file, "-o", output]
        cli_runner.invoke(nxpimage.main, cmd, expected_code=-1)


@pytest.mark.parametrize(
    "in_file,out_str,type,padding,endian,error",
    [
        ("inc9.bin", "0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,", None, None, None, False),
        (
            "inc9.bin",
            "0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,",
            None,
            None,
            Endianness.LITTLE,
            False,
        ),
        (
            "inc9.bin",
            "",
            "uint16_t",
            None,
            None,
            True,
        ),
        (
            "inc9.bin",
            "0x0001, 0x0203, 0x0405, 0x0607, 0x08aa,",
            "uint16_t",
            "0xAA",
            None,
            False,
        ),
        (
            "inc9.bin",
            "0x0100, 0x0302, 0x0504, 0x0706, 0xaa08,",
            "uint16_t",
            "0xAA",
            Endianness.LITTLE,
            False,
        ),
        (
            "inc9.bin",
            "",
            "uint32_t",
            None,
            None,
            True,
        ),
        (
            "inc9.bin",
            "0x00010203, 0x04050607, 0x08aabbcc,",
            "uint32_t",
            "0xAABBCC",
            None,
            False,
        ),
        (
            "inc9.bin",
            "0x03020100, 0x07060504, 0xccbbaa08,",
            "uint32_t",
            "0xAABBCC",
            Endianness.LITTLE,
            False,
        ),
        (
            "inc8.bin",
            "0x03020100, 0x07060504,",
            "uint32_t",
            None,
            Endianness.LITTLE,
            False,
        ),
        (
            "inc8.bin",
            "0x00010203, 0x04050607,",
            "uint32_t",
            None,
            Endianness.BIG,
            False,
        ),
    ],
)
def test_nxpimage_convert_bin2carr(
    cli_runner: CliRunner, data_dir, in_file, out_str, type, padding, endian, error
):
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/bin2carr/{in_file}"
        cmd = ["utils", "convert", "bin2carr", "-i", input_file]
        if type:
            cmd.extend(["-t", type])
        if padding:
            cmd.extend(["-p", padding])
        if endian is not None:
            cmd.extend(["-e", endian.value])
        result = cli_runner.invoke(nxpimage.main, cmd, expected_code=-1 if error else 0)
        if not error:
            assert out_str in result.output


def test_nxpimage_convert_bin2carr_file(cli_runner: CliRunner, tmpdir, data_dir):
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/bin2carr/inc9.bin"
        correct_output = f"{data_dir}/utils/convert/bin2carr/inc9_uint32_t.txt"
        output = f"{tmpdir}/inc9_uint32_t.txt"
        cmd = [
            "utils",
            "convert",
            "bin2carr",
            "-i",
            input_file,
            "-t",
            "uint32_t",
            "-p",
            "0xAABBCC",
            "-e",
            Endianness.LITTLE,
            "-o",
            output,
        ]
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.isfile(output)
        assert filecmp.cmp(output, correct_output, shallow=False)
