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
