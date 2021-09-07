#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of elftosb app."""
import filecmp
import os

from click.testing import CliRunner

from spsdk.apps import elftosb
from spsdk.utils.misc import use_working_directory


def test_elftosb_trustzone_basic(data_dir, tmpdir):
    runner = CliRunner()
    with use_working_directory(tmpdir):
        cmd = f"--tzm-conf {data_dir}/lpc55xxA1.json"
        result = runner.invoke(elftosb.main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/lpc55xxA1_tzFile.bin")
    assert filecmp.cmp(f"{data_dir}/lpc55xxA1_tzFile.bin", f"{tmpdir}/lpc55xxA1_tzFile.bin")
