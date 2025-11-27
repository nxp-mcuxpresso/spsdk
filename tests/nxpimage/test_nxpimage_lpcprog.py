#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP Image LPC Programming functionality tests.

This module contains unit tests for LPC programming capabilities within
the SPSDK nxpimage application, specifically testing CRP (Code Read Protection)
handling and bootable image creation for LPC devices.
"""

import os
from typing import Any

from spsdk import SPSDK_EXAMPLES_FOLDER
from spsdk.apps import nxpimage
from spsdk.lpcprog.protocol import LPCProgCRPLevels
from spsdk.lpcprog.utils import CRP_LENGTH, CRP_OFFSET
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner

EXAMPLE_APP = os.path.join(SPSDK_EXAMPLES_FOLDER, "_data", "lpcxpresso860_led_blinky.bin")


def test_lpcprog_update_crp_value(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test LPC programming CRP value update functionality.

    Verifies that the lpcprog set-crp command correctly updates the Code Read Protection
    (CRP) value in a binary file. The test sets CRP level to CRP3 and validates that
    the output binary contains the expected CRP bytes at the correct offset.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    # Test the function lpcprog_update_crp_value
    cmd = ["lpcprog", "set-crp", "-l", "CRP3", "-b", EXAMPLE_APP, "-o", "output.bin"]

    with use_working_directory(tmpdir):
        crp_value = LPCProgCRPLevels.CRP3.tag

        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.exists("output.bin")
        updated_bin_data = load_binary("output.bin")
        expected_crp_bytes = crp_value.to_bytes(CRP_LENGTH, byteorder="big")
        assert updated_bin_data[CRP_OFFSET : CRP_OFFSET + CRP_LENGTH] == expected_crp_bytes


def test_lpcprog_make_image_bootable(cli_runner: CliRunner, tmpdir: Any) -> None:
    """Test LPC programmer make image bootable functionality.

    Verifies that the lpcprog make-bootable command correctly processes a binary file
    and creates a bootable output image. The test ensures the command executes without
    errors and produces the expected output file with correct content.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param tmpdir: Temporary directory fixture for test file operations.
    """
    # Test the function lpcprog_make_image_bootable
    cmd = ["lpcprog", "make-bootable", "-b", EXAMPLE_APP, "-o", "output.bin"]

    with use_working_directory(tmpdir):
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.exists("output.bin")
        updated_bin_data = load_binary("output.bin")
        assert updated_bin_data == load_binary(EXAMPLE_APP)
