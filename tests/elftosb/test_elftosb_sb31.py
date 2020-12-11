#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test SecureBinary part of elftosb app."""
import json

from click.testing import CliRunner

from spsdk.apps import elftosb, elftosb_helper


def test_elftosb_sb31_basic(data_dir):
    cmd = f"--container-conf {data_dir}/lpc55xxA1.json"
    result = CliRunner().invoke(elftosb.main, cmd.split())
    assert isinstance(result.exception, NotImplementedError)


def test_elftosb_sb31_config(data_dir):
    with open(f"{data_dir}/sb3_256_256.json") as f:
        config_data = json.load(f)
    config = elftosb_helper.SB31Config(config_data)
    assert len(config.commands) == 2
