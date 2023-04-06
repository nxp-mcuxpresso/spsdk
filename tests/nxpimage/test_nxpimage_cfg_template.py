#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test Trustzone part of nxpimage app."""
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage


@pytest.mark.parametrize(
    "device",
    [("lpc55s3x")],
)
def test_nxpimage_cfgtmp_create_sb3(tmpdir, device):
    runner = CliRunner()
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"sb31 get-template -f {device} {file_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    # Check at least common TrustZone Configuration file
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device",
    [("rt118x")],
)
def test_nxpimage_cfgtmp_create_ahab(tmpdir, device):
    runner = CliRunner()
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"ahab get-template -f {device} {file_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    # Check at least common TrustZone Configuration file
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device,revision",
    [
        ("lpc55xx", "latest"),
        ("lpc55s0x", "latest"),
        ("lpc55s1x", "latest"),
        ("lpc55s6x", "latest"),
        ("lpc55s3x", "latest"),
        ("rt5xx", "latest"),
        ("rt6xx", "latest"),
        ("rt6xx", "a0"),
        ("rt6xx", "b0"),
    ],
)
def test_nxpimage_cfgtmp_create_tz(tmpdir, device, revision):
    runner = CliRunner()
    file_name = os.path.join(tmpdir, f"template_{device}_{revision}.yml")
    cmd = f"tz get-template -f {device} -r {revision} {file_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    # Check at least common TrustZone Configuration file
    assert os.path.isfile(file_name)


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
def test_nxpimage_cfgtmp_create_mbi(tmpdir, device):
    runner = CliRunner()
    cmd = f"mbi get-templates -f {device} {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
