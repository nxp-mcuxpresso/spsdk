#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for nxpimage configuration template functionality.

This module contains unit tests for the template generation capabilities
of the nxpimage application, covering various image types and configurations
including SB3.1, AHAB, TrustZone, and Master Boot Image templates.
"""

import os
from typing import Any

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
def test_nxpimage_get_template_create_sb31(cli_runner: CliRunner, tmpdir: Any, device: str) -> None:
    """Test nxpimage get-template command for SB31 configuration file generation.

    This test verifies that the nxpimage CLI can successfully generate a template
    configuration file for SB31 (Secure Binary 3.1) format for a specified device.
    The test creates a temporary file and validates that the template is properly
    generated.

    :param cli_runner: Click CLI test runner for invoking command line interface.
    :param tmpdir: Temporary directory fixture for creating test files.
    :param device: Target device name for which to generate the SB31 template.
    """
    file_name = os.path.join(tmpdir, "template.yml")
    cmd = f"sb31 get-template -f {device} --output {file_name}"
    cli_runner.invoke(nxpimage.main, cmd.split())
    assert os.path.isfile(file_name)


@pytest.mark.parametrize(
    "device",
    [("mimxrt1189"), ("mx93")],
)
def test_nxpimage_get_template_ahab(cli_runner: CliRunner, tmpdir: Any, device: str) -> None:
    """Test AHAB get-template command functionality.

    Verifies that the nxpimage CLI can successfully generate an AHAB template
    configuration file for a specified device and save it to the output path.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    :param device: Target device name for template generation.
    """
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
def test_nxpimage_get_template_tz(
    cli_runner: CliRunner, tmpdir: Any, device: str, revision: str
) -> None:
    """Test nxpimage TrustZone template generation functionality.

    This test verifies that the nxpimage CLI can successfully generate a TrustZone
    configuration template file for a specified device and revision, and that the
    output file is created at the expected location.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test file output.
    :param device: Target device name for template generation.
    :param revision: Device revision for template generation.
    """
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
def test_nxpimage_get_template_mbi(cli_runner: CliRunner, tmpdir: Any, device: str) -> None:
    """Test MBI get-templates command functionality.

    This test verifies that the nxpimage CLI can successfully generate MBI (Master Boot Image)
    configuration templates for a specified device and save them to the output directory.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory for test output files.
    :param device: Target device name for template generation.
    """
    cmd = f"mbi get-templates -f {device} --output {tmpdir}"
    cli_runner.invoke(nxpimage.main, cmd.split())
