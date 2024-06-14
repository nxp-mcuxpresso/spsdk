#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Testing the SDPHost application."""


import sys
from unittest.mock import patch

import spsdk
from spsdk.apps import sdphost
from spsdk.utils.serial_proxy import SerialProxy
from tests.cli_runner import CliRunner

data_responses = {
    b"\x05\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00": b"\x56\x78\x78\x56\xf0\xf0\xf0\xf0"
}


def test_version(cli_runner: CliRunner):
    result = cli_runner.invoke(sdphost.main, ["--version"])
    assert spsdk.__version__ in result.output


def test_get_property(cli_runner: CliRunner, caplog):
    # There's a problem with logging under CliRunner
    # https://github.com/pytest-dev/pytest/issues/3344
    # caplog is set to disable all logging output
    # Comment the following line to see logging info, however there will be an failure
    caplog.set_level(100_000)
    cmd = "-p com12 error-status"
    with patch(
        "spsdk.utils.interfaces.device.serial_device.Serial", SerialProxy.init_proxy(data_responses)
    ):
        result = cli_runner.invoke(sdphost.main, cmd.split())
        assert "Response status = 4042322160 (0xf0f0f0f0) HAB Success." in result.output


def test_sdphost_help(cli_runner: CliRunner, caplog):
    caplog.set_level(100_000)
    cmd = ["--help"]
    result = cli_runner.invoke(sdphost.main, cmd)
    assert "Utility for communication with ROM on i.MX" in str(result.output)
