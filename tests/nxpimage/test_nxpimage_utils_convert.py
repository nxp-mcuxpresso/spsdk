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
from spsdk.utils.misc import use_working_directory


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
def test_nxpimage_convert_hexbin(tmpdir, data_dir, in_file, out_file, command, reverse):
    runner = CliRunner()
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/hexbin/{in_file}"
        correct_ouput = f"{data_dir}/utils/convert/hexbin/{out_file}"
        output = f"{tmpdir}/{out_file}"
        cmd = f"utils convert {command} -i {input_file} {'-r' if reverse else ''} {output}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(output)
        assert filecmp.cmp(output, correct_ouput, shallow=False)


@pytest.mark.parametrize("in_file", [("inc_16.bin"), ("inc_16_invalid.hex")])
def test_nxpimage_convert_hexbin_invalid(tmpdir, data_dir, in_file):
    runner = CliRunner()
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/hexbin/{in_file}"
        output = f"{tmpdir}/test.bin"
        cmd = f"utils convert hex2bin -i {input_file} {output}"
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code != 0


@pytest.mark.parametrize(
    "in_file,out_str,type,padding,endian,error",
    [
        ("inc9.bin", "0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,", None, None, None, False),
        (
            "inc9.bin",
            "0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,",
            None,
            None,
            "little",
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
            "little",
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
            "little",
            False,
        ),
        (
            "inc8.bin",
            "0x03020100, 0x07060504,",
            "uint32_t",
            None,
            "little",
            False,
        ),
        (
            "inc8.bin",
            "0x00010203, 0x04050607,",
            "uint32_t",
            None,
            "big",
            False,
        ),
    ],
)
def test_nxpimage_convert_bin2carr(data_dir, in_file, out_str, type, padding, endian, error):
    runner = CliRunner()
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/bin2carr/{in_file}"
        cmd = f"utils convert bin2carr -i {input_file}"
        if type:
            cmd += f" -t {type}"
        if padding:
            cmd += f" -p {padding}"
        if endian:
            cmd += f" -e {endian}"
        result = runner.invoke(nxpimage.main, cmd.split())
        if error:
            assert result.exit_code != 0
        else:
            assert out_str in result.output


def test_nxpimage_convert_bin2carr_file(tmpdir, data_dir):
    runner = CliRunner()
    with use_working_directory(data_dir):
        input_file = f"{data_dir}/utils/convert/bin2carr/inc9.bin"
        correct_ouput = f"{data_dir}/utils/convert/bin2carr/inc9_uint32_t.txt"
        output = f"{tmpdir}/inc9_uint32_t.txt"
        cmd = (
            f"utils convert bin2carr -i {input_file} -t uint32_t -p 0xAABBCC -e little -o {output}"
        )
        result = runner.invoke(nxpimage.main, cmd.split())
        assert result.exit_code == 0
        assert os.path.isfile(output)
        assert filecmp.cmp(output, correct_ouput, shallow=False)
