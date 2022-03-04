#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of elftosb app."""
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import elftosb


@pytest.mark.parametrize(
    "device",
    [
        ("lpc55xx"),
        ("lpc55s0x"),
        ("lpc55s1x"),
        ("lpc55s6x"),
        ("lpc55s3x"),
        ("rt5xx"),
        ("rt6xx"),
    ],
)
def test_elftosb_cfgtmp_create(tmpdir, device):
    runner = CliRunner()

    cmd = f"-Y {tmpdir} -f {device}"
    result = runner.invoke(elftosb.main, cmd.split())
    assert result.exit_code == 0
    # Check at least common TrustZone Configuration file
    assert os.path.isfile(os.path.join(tmpdir, f"{device}_tz.yml"))
