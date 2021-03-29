#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpdebugmbox utility."""

from click.testing import CliRunner

from spsdk.apps.nxpdebugmbox import main
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

def test_command_line_interface_main():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ['--help'])
    assert result.exit_code == 0

    assert 'main [OPTIONS] COMMAND [ARGS]' in result.output
    assert 'NXP Debug Mailbox Tool.' in result.output
    assert '-i, --interface TEXT' in result.output
    assert '-p, --protocol VERSION' in result.output
    assert '-d, --debug LEVEL' in result.output
    assert '-s, --serial-no TEXT' in result.output
    assert 't, --timing FLOAT' in result.output
    assert '-n, --no-reset' in result.output
    assert '-o, --debug-probe-option TEXT' in result.output
    assert '-v, --version' in result.output
    assert '--help' in result.output
    assert 'auth     Perform the Debug Authentication.' in result.output
    assert 'erase    Erase Flash.' in result.output
    assert 'exit     Exit DebugMailBox.' in result.output
    assert 'famode   Set Fault Analysis Mode.' in result.output
    assert 'ispmode  Enter ISP Mode.' in result.output
    assert 'start    Start DebugMailBox.' in result.output

def test_command_line_interface_auth():
    """Test for auth menu options."""
    runner = CliRunner()
    cmd = f'auth --help'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert 'auth [OPTIONS]' in result.output
    assert 'Perform the Debug Authentication.' in result.output
    assert '-b, --beacon INTEGER    Authentication beacon' in result.output
    assert '-c, --certificate TEXT  Path to Debug Credentials.' in result.output
    assert '-k, --key TEXT          Path to DCK private key.' in result.output
    assert '-f, --force' in result.output
    assert '--help                  Show this message and exit.' in result.output

def test_command_line_interface_erase():
    """Test for erase menu options."""
    runner = CliRunner()
    cmd = f'erase --help'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert 'erase [OPTIONS]' in result.output
    assert 'Erase Flash.' in result.output
    assert '--help  Show this message and exit.' in result.output

def test_command_line_interface_exit():
    """Test for exit menu options."""
    runner = CliRunner()
    cmd = f'exit --help'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert 'exit [OPTIONS]' in result.output
    assert 'Exit DebugMailBox.' in result.output
    assert '--help  Show this message and exit.' in result.output

def test_command_line_interface_famode():
    """Test for famode menu options."""
    runner = CliRunner()
    cmd = f'famode --help'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert 'famode [OPTIONS]' in result.output
    assert 'Set Fault Analysis Mode.' in result.output
    assert '--help  Show this message and exit.' in result.output

def test_command_line_interface_ispmode():
    """Test for ispmode menu options."""
    runner = CliRunner()
    cmd = f'ispmode --help'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert 'ispmode [OPTIONS]' in result.output
    assert 'Enter ISP Mode.' in result.output
    assert '-m, --mode INTEGER  [required]' in result.output
    assert '--help              Show this message and exit.' in result.output

def test_command_line_interface_start():
    """Test for start menu options."""
    runner = CliRunner()
    cmd = f'start --help'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert 'start [OPTIONS]' in result.output
    assert 'Start DebugMailBox.' in result.output
    assert '--help  Show this message and exit.' in result.output


def test_nxpdebugmbox_invalid_probe_user_param():
    """Test for Invalid debug probe user params."""
    runner = CliRunner()
    cmd = f'-o user_par -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug start'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1

def test_nxpdebugmbox_invalid_probe():
    """Test for Invalid debug probe."""
    runner = CliRunner()
    cmd = f'-i virtual -d debug start'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    assert "There is no any debug probe connected in system!" in result.output

def test_nxpdebugmbox_valid_probe_user_param():
    """Test for Invalid debug probe user params."""
    runner = CliRunner()
    cmd = f'-o user_par=1 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug start'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

def test_nxpdebugmbox_start_exe():
    """Test for start command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f'-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug start'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

def test_nxpdebugmbox_exit_exe():
    """Test for exit command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f'-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug exit'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

def test_nxpdebugmbox_ispmode_exe():
    """Test for ispmode command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f'-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug ispmode -m 0'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

def test_nxpdebugmbox_famode_exe():
    """Test for famode command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f'-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug famode'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

def test_nxpdebugmbox_erase_exe():
    """Test for erase command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f'-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug erase'
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
