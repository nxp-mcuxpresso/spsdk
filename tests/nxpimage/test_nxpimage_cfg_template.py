#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test getting templates part of nxpimage app."""
import os

import pytest
from click.testing import CliRunner

from spsdk.apps import nxpimage


@pytest.mark.parametrize(
    "device",
    [
        ("lpc55s3x"),
        ("k32w1xx"),
        ("kw45xx"),
        ("mcxn9xx"),
        ("rw61x"),
    ],
)
def test_nxpimage_get_template_create_sb31(tmpdir, device):
    runner = CliRunner()
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"sb31 get-template -f {device} --output {file_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device",
    [("rt118x"), ("mx93")],
)
def test_nxpimage_get_template_ahab(tmpdir, device):
    runner = CliRunner()
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"ahab get-template -f {device} --output {file_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device,revision",
    [
        ("lpc55s0x", "latest"),
        ("lpc55s1x", "latest"),
        ("lpc55s6x", "latest"),
        ("lpc55s3x", "latest"),
        ("rt5xx", "latest"),
        ("rt6xx", "latest"),
        ("rt6xx", "a0"),
        ("rt6xx", "b0"),
        ("k32w1xx", "latest"),
        ("kw45xx", "latest"),
        ("mcxn9xx", "latest"),
        ("nhs52s04", "latest"),
    ],
)
def test_nxpimage_get_template_tz(tmpdir, device, revision):
    runner = CliRunner()
    file_name = os.path.join(tmpdir, f"template_{device}_{revision}.yml")
    cmd = f"tz get-template -f {device} -r {revision} --output {file_name}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device",
    [
        ("lpc55s0x"),
        ("lpc550x"),
        ("lpc55s1x"),
        ("lpc551x"),
        ("lpc55s2x"),
        ("lpc552x"),
        ("lpc55s6x"),
        ("lpc55s3x"),
        ("lpc553x"),
        ("rt5xx"),
        ("rt6xx"),
        ("kw45xx"),
        ("k32w1xx"),
        ("mcxn9xx"),
        ("nhs52sxx"),
        ("mc56f81xxx"),
        ("mwct20d2x"),
        ("rw61x"),
    ],
)
def test_nxpimage_get_template_mbi(tmpdir, device):
    runner = CliRunner()
    cmd = f"mbi get-templates -f {device} --output {tmpdir}"
    result = runner.invoke(nxpimage.main, cmd.split())
    assert result.exit_code == 0
