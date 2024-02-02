#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for shadow registers utility."""
import os

import pytest

from spsdk.apps.shadowregs import main
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main(cli_runner: CliRunner):
    """Test for main menu options."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


# This is testing none connected any probe
def test_command_line_interface_printregs_no_probe_exe(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    cmd = "-f rt5xx -i virtual printregs"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_invalid_device(cli_runner: CliRunner):
    """Test for reset execution menu options."""
    cmd = "-f invalid -i virtual reset"
    cli_runner.invoke(main, cmd.split(), expected_code=-1)


def test_command_line_interface_printregs_exe_fail(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    disable_debug = "-o mem_read_exp=1"
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {disable_debug} printregs"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_printregs_exe(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_printregs_r_exe(cli_runner: CliRunner):
    """Test for printregs rich execution menu options."""
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs -r"
    result = cli_runner.invoke(main, cmd.split())
    assert "Register description:" in result.output


def test_command_line_interface_setreg_exe(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += " setreg -r DCFG_CC_SOCU -v 12345678"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_getreg_exe(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r DCFG_CC_SOCU"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_saveloadconfig_exe(cli_runner: CliRunner, tmpdir):
    """Test for saveconfig execution menu options."""
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    result = cli_runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    # check if the file really exists
    assert os.path.isfile(filename)

    # Try to load the generated file
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -c {filename}"
    result = cli_runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_reset_exe(cli_runner: CliRunner):
    """Test for reset execution menu options."""
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} reset"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_logger(cli_runner: CliRunner):
    """Test for reset execution menu options."""
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -vv reset"
    cli_runner.invoke(main, cmd.split())


def test_command_line_interface_invalid_o_param(cli_runner: CliRunner):
    """Test for reset execution menu options."""
    enable_debug = "-o subs_ap"
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -vv reset"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_saveconfig_exe_fail(cli_runner: CliRunner, tmpdir):
    """Test for saveconfig rich execution menu options."""
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_loadconfig_exe_fail(cli_runner: CliRunner, data_dir):
    """Test for saveconfig rich execution menu options."""
    # create path in TMP DIR
    filename = os.path.join(data_dir, "sh_regs_corrupted.yml")
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = [
        "-f",
        "rt5xx",
        "-i",
        "virtual",
        "-s",
        DebugProbeVirtual.UNIQUE_SERIAL,
        enable_debug,
        "loadconfig",
        "-c",
        filename,
    ]
    cli_runner.invoke(main, cmd, expected_code=1)


def test_command_line_interface_printregs_exe_fail1(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_setreg_exe_fail(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += " setreg -r CUST_WR_RD_LOCK0 -v 12345678"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_getreg_exe_fail(cli_runner: CliRunner):
    """Test for printregs execution menu options."""
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r CUST_WR_RD_LOCK0"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_command_line_interface_fuse_script_exe(cli_runner: CliRunner, tmpdir):
    """Test for saveconfig rich execution menu options."""
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    cli_runner.invoke(main, cmd.split())
    # check if the file really exists
    assert os.path.isfile(filename)

    # Try create BLHOST script
    script_file = os.path.join(tmpdir, "blhost_script.bsf")
    cmd = f"-f rt5xx fuses-script -c {filename} -o {script_file}"
    cli_runner.invoke(main, cmd.split())
    # check if the file really exists
    assert os.path.isfile(script_file)


@pytest.mark.parametrize(
    "family",
    [
        ("rt5xx"),
        ("rt6xx"),
        ("rw61x"),
    ],
)
def test_command_line_get_template(cli_runner: CliRunner, tmpdir, family):
    """Test for get template in shadowregs."""
    cmd = f"--family {family} get-template --output {tmpdir}/shadowregs.yml"
    cli_runner.invoke(main, cmd.split())
    assert os.path.isfile(f"{tmpdir}/shadowregs.yml")
