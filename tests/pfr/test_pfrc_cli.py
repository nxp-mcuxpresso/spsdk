#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module for PRFC CLI tool."""
from click.testing import CliRunner

from spsdk.apps import pfrc


def test_pfrc_basic_cli(data_dir):
    """Test PFR Checker tool."""
    cmd = f"-m {data_dir}/cmpa_pfrc.json -f {data_dir}/cfpa_pfrc.json -r {data_dir}/rules.json"
    result = CliRunner().invoke(pfrc.main, cmd.split())
    assert result.exit_code == 0
