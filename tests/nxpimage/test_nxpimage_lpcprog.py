#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os
from spsdk import SPSDK_EXAMPLES_FOLDER

from spsdk.apps import nxpimage
from spsdk.lpcprog.utils import CRP_LENGTH, CRP_OFFSET
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner

from spsdk.lpcprog.protocol import LPCProgCRPLevels

EXAMPLE_APP = os.path.join(SPSDK_EXAMPLES_FOLDER, "_data", "lpcxpresso860_led_blinky.bin")


def test_lpcprog_update_crp_value(cli_runner: CliRunner, tmpdir):
    # Test the function lpcprog_update_crp_value
    cmd = ["lpcprog", "set-crp", "-l", "CRP3", "-b", EXAMPLE_APP, "-o", "output.bin"]

    with use_working_directory(tmpdir):
        crp_value = LPCProgCRPLevels.CRP3.tag

        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.exists("output.bin")
        updated_bin_data = load_binary("output.bin")
        expected_crp_bytes = crp_value.to_bytes(CRP_LENGTH, byteorder="little")
        assert updated_bin_data[CRP_OFFSET : CRP_OFFSET + CRP_LENGTH] == expected_crp_bytes


def test_lpcprog_make_image_bootable(cli_runner: CliRunner, tmpdir):
    # Test the function lpcprog_make_image_bootable
    cmd = ["lpcprog", "make-bootable", "-b", EXAMPLE_APP, "-o", "output.bin"]

    with use_working_directory(tmpdir):
        cli_runner.invoke(nxpimage.main, cmd)
        assert os.path.exists("output.bin")
        updated_bin_data = load_binary("output.bin")
        assert updated_bin_data == load_binary(EXAMPLE_APP)
