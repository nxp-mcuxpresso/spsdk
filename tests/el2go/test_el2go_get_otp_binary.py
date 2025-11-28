#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK EL2GO OTP binary generation tests.

This module contains unit tests for the EL2GO application's OTP (One-Time Programmable)
binary generation functionality, specifically testing the secure configuration workflow.
"""

import filecmp
import os

import pytest

from spsdk.apps import el2go
from tests.cli_runner import CliRunner


@pytest.mark.xfail()
@pytest.mark.parametrize(
    "config_file, ref_binary",
    [
        ("otp_using_names.yaml", "el2go_otp.bin"),
        ("otp_using_uids.yaml", "el2go_otp.bin"),
    ],
)
def test_el2go_otp_binary_sec_config(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, config_file: str, ref_binary: str
) -> None:
    """Test EL2GO OTP binary generation with security configuration.

    This test verifies that the EL2GO get-otp-binary command correctly generates
    an OTP binary file from a security configuration and matches the expected
    reference binary output.

    :param cli_runner: CLI test runner for invoking commands.
    :param data_dir: Directory path containing test data files.
    :param tmpdir: Temporary directory path for output files.
    :param config_file: Name of the configuration file to use.
    :param ref_binary: Name of the reference binary file for comparison.
    """
    config = os.path.join(data_dir, config_file)
    ref_file = os.path.join(data_dir, ref_binary)
    out_file = os.path.join(tmpdir, "el2go_otp.bin")

    cmd = f"get-otp-binary -c {config} -o {out_file}"

    cli_runner.invoke(el2go.main, cmd.split(), expected_code=0)
    assert os.path.isfile(out_file)
    assert filecmp.cmp(ref_file, out_file)
