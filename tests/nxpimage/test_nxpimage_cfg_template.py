#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test getting templates part of nxpimage app."""
import os

import pytest

from spsdk.apps import nxpimage
from tests.cli_runner import CliRunner


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
def test_nxpimage_get_template_create_sb31(cli_runner: CliRunner, tmpdir, device):
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"sb31 get-template -f {device} --output {file_name}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device",
    [("mimxrt1189"), ("mx93")],
)
def test_nxpimage_get_template_ahab(cli_runner: CliRunner, tmpdir, device):
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"ahab get-template -f {device} --output {file_name}"
    cli_runner.invoke(nxpimage.main, cmd.split())
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
        ("nhs52sxx", "latest"),
    ],
)
def test_nxpimage_get_template_tz(cli_runner: CliRunner, tmpdir, device, revision):
    file_name = os.path.join(tmpdir, f"template_{device}_{revision}.yml")
    cmd = f"tz get-template -f {device} -r {revision} --output {file_name}"
    cli_runner.invoke(nxpimage.main, cmd.split())
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
        ("mc56f818xx"),
        ("mwct2xd2"),
        ("rw61x"),
    ],
)
def test_nxpimage_get_template_mbi(cli_runner: CliRunner, tmpdir, device):
    cmd = f"mbi get-templates -f {device} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
