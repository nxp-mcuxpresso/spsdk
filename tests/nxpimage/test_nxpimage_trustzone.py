#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of elftosb app."""
import filecmp
import os

from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_text, use_working_directory, write_file


def test_nxpimage_trustzone_basic(elftosb_data_dir, tmpdir):
    runner = CliRunner()
    with use_working_directory(tmpdir):
        write_file(load_text(f"{elftosb_data_dir}/lpc55xxA1.json"), "lpc55xxA1.json")
        cmd = "tz export lpc55xxA1.json"
        result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(f"{tmpdir}/lpc55xxA1_tzFile.bin")
    assert filecmp.cmp(f"{elftosb_data_dir}/lpc55xxA1_tzFile.bin", f"{tmpdir}/lpc55xxA1_tzFile.bin")
