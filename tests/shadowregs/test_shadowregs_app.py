#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for shadow registers utility."""
import os

import pytest
from click.testing import CliRunner

from spsdk.apps.shadowregs import main
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Show this message and exit." in result.output


@pytest.mark.parametrize(
    "cmd",
    [
        "getreg --help",
        "loadconfig --help",
        "printregs --help",
        "saveconfig --help",
        "setreg --help",
    ],
)
def test_command_line_interface_getreg(cmd):
    """Test for getreg menu options."""
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    assert "Show this message and exit." in result.output


# This is testing none connected any probe
def test_command_line_interface_printregs_no_probe_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    cmd = "-f rt5xx -i virtual printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_invalid_device():
    """Test for reset execution menu options."""
    runner = CliRunner()
    cmd = "-f invalid -i virtual reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code != 0


def test_command_line_interface_printregs_exe_fail():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    disable_debug = "-o mem_read_exp=1"
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {disable_debug} printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_printregs_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0


def test_command_line_interface_printregs_r_exe():
    """Test for printregs rich execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs -r"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0

    assert "Register description:" in result.output


def test_command_line_interface_setreg_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += " setreg -r DCFG_CC_SOCU -v 12345678"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0


def test_command_line_interface_getreg_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r DCFG_CC_SOCU"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0


def test_command_line_interface_saveloadconfig_r_exe(tmpdir):
    """Test for saveconfig rich execution menu options."""
    runner = CliRunner()
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename} -r"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    # check if the file really exists
    assert os.path.isfile(filename)

    # Try to load the generated file
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -c {filename} -r"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_saveloadconfig_exe(tmpdir):
    """Test for saveconfig execution menu options."""
    runner = CliRunner()
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    # check if the file really exists
    assert os.path.isfile(filename)

    # Try to load the generated file
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -c {filename}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_reset_exe():
    """Test for reset execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_logger():
    """Test for reset execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -vv reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_invalid_o_param():
    """Test for reset execution menu options."""
    runner = CliRunner()
    enable_debug = "-o subs_ap"
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -vv reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1


def test_command_line_interface_saveconfig_exe_fail(tmpdir):
    """Test for saveconfig rich execution menu options."""
    runner = CliRunner()
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1


def test_command_line_interface_loadconfig_exe_fail(data_dir):
    """Test for saveconfig rich execution menu options."""
    runner = CliRunner()
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
    result = runner.invoke(main, cmd)
    assert result.exit_code == 1


def test_command_line_interface_printregs_exe_fail1():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_setreg_exe_fail():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += " setreg -r CUST_WR_RD_LOCK0 -v 12345678"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_getreg_exe_fail():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r CUST_WR_RD_LOCK0"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_generate_html(tmpdir):
    """Test for info execution menu options."""
    runner = CliRunner()
    cmd = f"-f rt5xx info -o {tmpdir}/imxrt_info.html"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0, result.output
    assert os.path.isfile(f"{tmpdir}/imxrt_info.html")


def test_command_line_interface_fuse_script_exe(tmpdir):
    """Test for saveconfig rich execution menu options."""
    runner = CliRunner()
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-f rt5xx -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -o {filename} -r"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    # check if the file really exists
    assert os.path.isfile(filename)

    # Try create BLHOST script
    script_file = os.path.join(tmpdir, "blhost_script.bsf")
    cmd = f"-f rt5xx fuses-script -c {filename} -o {script_file}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
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
def test_command_line_get_template(tmpdir, family):
    """Test for get template in shadowregs."""
    cmd = f"--family {family} get-template --output {tmpdir}/shadowregs.yml"
    runner = CliRunner()
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    assert os.path.isfile(f"{tmpdir}/shadowregs.yml")
