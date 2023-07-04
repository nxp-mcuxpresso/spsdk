#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for `dk6_tools` package."""
import platform

from click.testing import CliRunner

from spsdk.apps import dk6prog


def test_cli():
    """Test the CLI."""
    runner = CliRunner()
    result = runner.invoke(dk6prog.main)
    assert result.exit_code == 0
    assert "Usage: dk6prog [OPTIONS] COMMAND1" in result.output
    help_result = runner.invoke(dk6prog.main, ["--help"])
    assert help_result.exit_code == 0
    assert "Usage: dk6prog [OPTIONS] COMMAND1" in help_result.output


def test_cli_listdev():
    """Test the CLI listdev command."""
    if platform.system() == "Windows":
        # Test needs FTD2xx.DLL
        return
    runner = CliRunner()
    result = runner.invoke(dk6prog.main, "listdev")
    assert result.exit_code == 0
    assert "List of available devices:" in result.output


def test_cli_erase():
    """Test the CLI erase command."""
    runner = CliRunner()
    result = runner.invoke(dk6prog.main, "erase --help")
    assert result.exit_code == 0
    assert "Erase the content of memory at the given <ADDRESS>" in result.output


def test_cli_read():
    """Test the CLI read command."""
    runner = CliRunner()
    result = runner.invoke(dk6prog.main, "read --help")
    assert result.exit_code == 0
    assert "Reads the memory and writes it to the file or stdout." in result.output


def test_cli_info():
    """Test the CLI info command."""
    runner = CliRunner()
    result = runner.invoke(dk6prog.main, "info")
    assert result.exit_code == 1
    # assert "Issues ISP sequence as defined in Driver interface." in result.output
