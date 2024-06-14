#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `dk6_tools` package."""

from spsdk.apps import dk6prog
from tests.cli_runner import CliRunner


def test_cli(cli_runner: CliRunner):
    """Test the CLI."""
    result = cli_runner.invoke(dk6prog.main)
    assert "Usage: dk6prog [OPTIONS] COMMAND1" in result.output
    result = cli_runner.invoke(dk6prog.main, ["--help"])
    assert "Usage: dk6prog [OPTIONS] COMMAND1" in result.output


def test_cli_listdev(cli_runner: CliRunner):
    """Test the CLI listdev command."""
    result = cli_runner.invoke(dk6prog.main, "--backend PYSERIAL listdev")
    assert "List of available devices:" in result.output


def test_cli_erase(cli_runner: CliRunner):
    """Test the CLI erase command."""
    result = cli_runner.invoke(dk6prog.main, "--backend PYSERIAL erase --help")
    assert "Erase the content of memory at the given <ADDRESS>" in result.output


def test_cli_read(cli_runner: CliRunner):
    """Test the CLI read command."""
    result = cli_runner.invoke(dk6prog.main, "--backend PYSERIAL read --help")
    assert "Reads the memory and writes it to the file or stdout." in result.output


def test_cli_info(cli_runner: CliRunner):
    """Test the CLI info command."""
    cli_runner.invoke(dk6prog.main, "--backend PYSERIAL info", expected_code=1)
    # assert "Issues ISP sequence as defined in Driver interface." in result.output
