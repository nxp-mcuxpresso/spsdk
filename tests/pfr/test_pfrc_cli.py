#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for PRFC CLI tool."""
from click.testing import CliRunner

from spsdk.apps import pfrc


def test_pfrc_basic_cli(data_dir):
    """Test PFR Checker tool."""
    cmd = f"-m {data_dir}/cmpa_pfrc.yml -f {data_dir}/cfpa_pfrc.yml"
    result = CliRunner().invoke(pfrc.main, cmd.split())
    assert result.exit_code == 0


def test_pfrc_basic_lpc55s3x_cli(data_dir):
    """Test PFR Checker tool."""
    cmd = f"-m {data_dir}/cmpa_pfrc_lpc55s3x.yml -f {data_dir}/cfpa_pfrc_lpc55s3x.yml"
    result = CliRunner().invoke(pfrc.main, cmd.split())
    assert result.exit_code == 0
