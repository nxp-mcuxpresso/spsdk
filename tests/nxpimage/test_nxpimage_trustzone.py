#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of nxpimage app."""
import filecmp
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage
from spsdk.utils.misc import load_text, use_working_directory, write_file


@pytest.fixture(scope="module")
def tz_data_dir(data_dir):
    return f"{data_dir}/tz"


def test_nxpimage_trustzone_basic(tz_data_dir, tmpdir):
    runner = CliRunner()
    with use_working_directory(tmpdir):
        write_file(load_text(f"{tz_data_dir}/lpc55s6xA1.yaml"), "lpc55s6xA1.yaml")
        cmd = "tz export -c lpc55s6xA1.yaml"
        result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(f"{tmpdir}/lpc55s6xA1_tzFile.bin")
    assert filecmp.cmp(f"{tz_data_dir}/lpc55s6xA1_tzFile.bin", f"{tmpdir}/lpc55s6xA1_tzFile.bin")
