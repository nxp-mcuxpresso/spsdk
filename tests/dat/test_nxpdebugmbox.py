#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpdebugmbox utility."""
import filecmp
import os

from click.testing import CliRunner

from spsdk.apps.nxpdebugmbox import main
from spsdk.utils.misc import use_working_directory
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0

    assert "main [OPTIONS] COMMAND [ARGS]" in result.output
    assert "NXP 'Debug Mailbox'/'Debug Credential file generator' Tool." in result.output
    assert "-i, --interface TEXT" in result.output
    assert "-p, --protocol VERSION" in result.output
    assert "-d, --debug LEVEL" in result.output
    assert "-s, --serial-no TEXT" in result.output
    assert "t, --timing FLOAT" in result.output
    assert "-n, --no-reset" in result.output
    assert "-o, --debug-probe-option TEXT" in result.output
    assert "-v, --version" in result.output
    assert "--help" in result.output
    assert "auth              Perform the Debug Authentication." in result.output
    assert "erase             Erase Flash." in result.output
    assert "exit              Exit DebugMailBox." in result.output
    assert "famode            Set Fault Analysis Mode." in result.output
    assert "gendc             Generate debug certificate (DC)." in result.output
    assert "get-cfg-template  Generate the template of Debug Credentials YML..." in result.output
    assert "ispmode           Enter ISP Mode." in result.output
    assert "start             Start DebugMailBox." in result.output


def test_command_line_interface_auth():
    """Test for auth menu options."""
    runner = CliRunner()
    cmd = "auth --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "auth [OPTIONS]" in result.output
    assert "Perform the Debug Authentication." in result.output
    assert "-b, --beacon INTEGER    Authentication beacon" in result.output
    assert "-c, --certificate TEXT  Path to Debug Credentials." in result.output
    assert "-k, --key TEXT          Path to DCK private key." in result.output
    assert "-n, --no-exit" in result.output
    assert "--help                  Show this message and exit." in result.output


def test_command_line_interface_erase():
    """Test for erase menu options."""
    runner = CliRunner()
    cmd = "erase --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "erase [OPTIONS]" in result.output
    assert "Erase Flash." in result.output
    assert "--help  Show this message and exit." in result.output


def test_command_line_interface_exit():
    """Test for exit menu options."""
    runner = CliRunner()
    cmd = "exit --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "exit [OPTIONS]" in result.output
    assert "Exit DebugMailBox." in result.output
    assert "--help  Show this message and exit." in result.output


def test_command_line_interface_famode():
    """Test for famode menu options."""
    runner = CliRunner()
    cmd = "famode --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "famode [OPTIONS]" in result.output
    assert "Set Fault Analysis Mode." in result.output
    assert "--help  Show this message and exit." in result.output


def test_command_line_interface_ispmode():
    """Test for ispmode menu options."""
    runner = CliRunner()
    cmd = "ispmode --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "ispmode [OPTIONS]" in result.output
    assert "Enter ISP Mode." in result.output
    assert "-m, --mode INTEGER  [required]" in result.output
    assert "--help              Show this message and exit." in result.output


def test_command_line_interface_start():
    """Test for start menu options."""
    runner = CliRunner()
    cmd = "start --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "start [OPTIONS]" in result.output
    assert "Start DebugMailBox." in result.output
    assert "--help  Show this message and exit." in result.output


def test_nxpdebugmbox_invalid_probe_user_param():
    """Test for Invalid debug probe user params."""
    runner = CliRunner()
    cmd = f"-o user_par -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug start"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1


def test_nxpdebugmbox_invalid_probe():
    """Test for Invalid debug probe."""
    runner = CliRunner()
    cmd = "-i virtual -d debug start"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1
    assert "There is no any debug probe connected in system!" in result.output


def test_nxpdebugmbox_valid_probe_user_param():
    """Test for Invalid debug probe user params."""
    runner = CliRunner()
    cmd = f"-o user_par=1 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug start"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_nxpdebugmbox_start_exe():
    """Test for start command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug start"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_nxpdebugmbox_exit_exe():
    """Test for exit command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug exit"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_nxpdebugmbox_ispmode_exe():
    """Test for ispmode command of nxp debug mailbox."""
    runner = CliRunner()
    hw_responses = '-o subs_ap={"33554440":[107941,0]}'
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {hw_responses} -d debug ispmode -m 0"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_nxpdebugmbox_famode_exe():
    """Test for famode command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug famode"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_nxpdebugmbox_erase_exe():
    """Test for erase command of nxp debug mailbox."""
    runner = CliRunner()
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -d debug erase"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_generate_rsa_dc_file(tmpdir, data_dir):
    """Test generate dc file with rsa 2048 protocol."""
    out_file = f"{tmpdir}/dc_2048.cert"
    cmd = f"gendc -c new_dck_rsa2048.yml -p 1.0 {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_ecc_dc_file(tmpdir, data_dir):
    """Test generate dc file with ecc protocol."""
    out_file = f"{tmpdir}/dc_secp256r1.cert"
    cmd = f"gendc -p 2.0 -c new_dck_secp256.yml {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_dc_file_lpc55s3x_256(tmpdir, data_dir):
    """Test generate dc file with ecc protocol for lpc55s3x"""
    out_file = f"{tmpdir}/dc_secp256r1_lpc55s3x.cert"
    cmd = f"gendc -p 2.0 -c new_dck_secp256_lpc55s3x.yml {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_dc_file_lpc55s3x_384(tmpdir, data_dir):
    """Test generate dc file with ecc protocol for lpc55s3x"""
    out_file = f"{tmpdir}/dc_secp384r1_lpc55s3x.cert"
    cmd = f"gendc -p 2.1 -c new_dck_secp384_lpc55s3x.yml {out_file}"
    with use_working_directory(data_dir):
        runner = CliRunner()
        result = runner.invoke(main, cmd.split())
        assert result.exit_code == 0, result.output
        assert os.path.isfile(out_file)


def test_generate_rsa_with_elf2sb(tmpdir, data_dir):
    org_file = f"{tmpdir}/org.dc"
    new_file = f"{tmpdir}/new.dc"

    cmd1 = f"gendc -p 1.0 -c org_dck_rsa_2048.yml {org_file}"
    # keys were removed from yaml and suplied by elf2sb config
    cmd2 = f"gendc -p 1.0 -c no_key_dck_rsa_2048.yml -e elf2sb_config.json {new_file}"
    with use_working_directory(data_dir):
        result = CliRunner().invoke(main, cmd1.split())
        assert result.exit_code == 0, result.output
        result = CliRunner().invoke(main, cmd2.split())
        assert result.exit_code == 0, result.output
    assert filecmp.cmp(org_file, new_file)
