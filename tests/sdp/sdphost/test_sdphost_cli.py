#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDPHost CLI application tests.

This module contains unit tests for the SDPHost command-line interface,
verifying proper functionality of SDP (Serial Download Protocol) host
operations and CLI argument handling.
"""

from typing import Any
from unittest.mock import patch

import spsdk
from spsdk.apps import sdphost
from spsdk.utils.serial_proxy import SerialProxy
from tests.cli_runner import CliRunner

data_responses = {
    b"\x05\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00": b"\x56\x78\x78\x56\xf0\xf0\xf0\xf0"
}


def test_version(cli_runner: CliRunner) -> None:
    """Test that sdphost CLI displays version information correctly.

    Verifies that the --version flag outputs the current SPSDK version string
    in the command line interface response.

    :param cli_runner: Click CLI test runner for invoking command line interfaces.
    """
    result = cli_runner.invoke(sdphost.main, ["--version"])
    assert spsdk.__version__ in result.output


def test_get_property(cli_runner: CliRunner, caplog: Any) -> None:
    """Test SDP host CLI get property command functionality.

    This test verifies that the SDP host CLI can successfully execute the error-status
    command and receive the expected HAB Success response. It uses a mocked serial
    interface to simulate device communication without requiring actual hardware.

    :param cli_runner: Click CLI test runner for invoking command line interfaces.
    :param caplog: Pytest fixture for capturing and controlling log output during tests.
    """
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


def test_sdphost_help(cli_runner: CliRunner, caplog: Any) -> None:
    """Test that sdphost CLI displays correct help message.

    Verifies that the sdphost command line interface shows the expected help text
    containing the utility description when invoked with --help flag.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param caplog: Pytest logging capture fixture for controlling log levels.
    """
    caplog.set_level(100_000)
    cmd = ["--help"]
    result = cli_runner.invoke(sdphost.main, cmd)
    assert "Utility for communication with ROM on i.MX" in str(result.output)
