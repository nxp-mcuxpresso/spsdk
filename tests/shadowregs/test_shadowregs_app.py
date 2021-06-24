#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for shadow registers utility."""
import os

from click.testing import CliRunner

from spsdk.apps.shadowregs import main
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main():
    """Test for main menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0

    assert "main [OPTIONS] COMMAND [ARGS]" in result.output
    assert "NXP Shadow Registers control Tool." in result.output
    assert "-i, --interface TEXT" in result.output
    assert "-d, --debug LEVEL" in result.output
    assert "-s, --serial-no TEXT" in result.output
    assert "-dev, --device TEXT" in result.output
    assert "-o, --debug-probe-option TEXT" in result.output
    assert "-v, --version" in result.output
    assert "--help" in result.output
    assert (
        "getreg      The command prints the current value of one shadow register." in result.output
    )
    assert "listdevs    The command prints a list of supported devices." in result.output
    assert "loadconfig  Load new state of shadow registers from YML file into" in result.output
    assert (
        "printregs   Print all Shadow registers including theirs current values." in result.output
    )
    assert "reset       The command resets connected device." in result.output
    assert "saveconfig  Save current state of shadow registers to YML file." in result.output
    assert "setreg      The command sets a value of one shadow register defined by" in result.output


def test_command_line_interface_getreg():
    """Test for getreg menu options."""
    runner = CliRunner()
    cmd = f"getreg --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "getreg [OPTIONS]" in result.output
    assert "-r, --reg TEXT" in result.output
    assert "--help" in result.output


def test_command_line_interface_listdevs():
    """Test for listdevs menu options."""
    runner = CliRunner()
    cmd = f"listdevs --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "listdevs [OPTIONS]" in result.output
    assert "--help" in result.output


def test_command_line_interface_loadconfig():
    """Test for loadconfig menu options."""
    runner = CliRunner()
    cmd = f"loadconfig --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "loadconfig [OPTIONS]" in result.output
    assert (
        "-f, --filename TEXT  The name of file used to load a new configuration." in result.output
    )
    assert (
        "-r, --raw            In loaded configuration will accepted also the computed"
        in result.output
    )
    assert "--help" in result.output


def test_command_line_interface_printregs():
    """Test for printregs menu options."""
    runner = CliRunner()
    cmd = f"printregs --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "printregs [OPTIONS]" in result.output
    assert "-r, --rich  Enables rich format of printed output." in result.output
    assert "--help" in result.output


def test_command_line_interface_saveconfig():
    """Test for saveconfig menu options."""
    runner = CliRunner()
    cmd = f"saveconfig --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "saveconfig [OPTIONS]" in result.output
    assert "-f, --filename TEXT  The name of file used to save the current" in result.output
    assert (
        "-r, --raw            The stored configuration will include also the computed"
        in result.output
    )
    assert "--help" in result.output


def test_command_line_interface_setreg():
    """Test for setreg menu options."""
    runner = CliRunner()
    cmd = f"setreg --help"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    assert "setreg [OPTIONS]" in result.output
    assert "-r, --reg TEXT      The name of register to be set." in result.output
    assert "-v, --reg_val TEXT  The new value of register in hex format." in result.output
    assert "--help" in result.output


# The execution tests
def test_command_line_interface_listdevs_exe():
    """Test for listdevs execution menu options."""
    runner = CliRunner()
    result = runner.invoke(main, ["listdevs"])
    assert result.exit_code == 0

    assert "imxrt595" in result.output
    assert "imxrt685" in result.output


# This is testing none connected any probe
def test_command_line_interface_printregs_no_probe_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    cmd = f"-dev imxrt595 -i virtual printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_invalid_device():
    """Test for reset execution menu options."""
    runner = CliRunner()
    cmd = f"-dev invalid -i virtual reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1


def test_command_line_interface_printregs_exe_fail():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    disable_debug = '-o subs_ap={"12":["Exception","Exception"]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {disable_debug} printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_printregs_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0


def test_command_line_interface_printregs_r_exe():
    """Test for printregs rich execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = (
        f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs -r"
    )
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0

    assert "Register description:" in result.output


def test_command_line_interface_setreg_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += f" setreg -r DCFG_CC_SOCU -v 12345678"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0


def test_command_line_interface_getreg_exe():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r DCFG_CC_SOCU"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0


def test_command_line_interface_saveloadconfig_r_exe(tmpdir):
    """Test for saveconfig rich execution menu options."""
    runner = CliRunner()
    # create path in TMP DIR
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -f {filename} -r"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0
    # check if the file really exists
    assert os.path.isfile(filename)

    # Try to load the generated file
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -f {filename} -r"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_saveloadconfig_exe(tmpdir):
    """Test for saveconfig execution menu options."""
    runner = CliRunner()
    filename = os.path.join(tmpdir, "SR_COV_TEST.yml")
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -f {filename}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0

    # check if the file really exists
    assert os.path.isfile(filename)

    # Try to load the generated file
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -f {filename}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_reset_exe():
    """Test for reset execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_logger():
    """Test for reset execution menu options."""
    runner = CliRunner()
    enable_debug = '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]}'
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -d debug reset"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 0


def test_command_line_interface_invalid_o_param():
    """Test for reset execution menu options."""
    runner = CliRunner()
    enable_debug = "-o subs_ap"
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} -d debug reset"
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
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} saveconfig -f {filename}"
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
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} loadconfig -f {filename}"
    result = runner.invoke(main, cmd.split())
    assert result.exit_code == 1


def test_command_line_interface_printregs_exe_fail1():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} printregs"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_setreg_exe_fail():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug}"
    cmd += f" setreg -r CUST_WR_RD_LOCK0 -v 12345678"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_getreg_exe_fail():
    """Test for printregs execution menu options."""
    runner = CliRunner()
    enable_debug = (
        '-o subs_ap={"12":["Exception",12345678],"33554432":[2,0,2,0],"33554440":[0]} '
        '-o subs_mem={"1074987040":["Exception"]}'
    )
    cmd = f"-dev imxrt595 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {enable_debug} getreg -r CUST_WR_RD_LOCK0"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 1


def test_command_line_interface_generate_html(tmpdir):
    """Test for info execution menu options."""
    runner = CliRunner()
    cmd = f"-dev imxrt595 info -o {tmpdir}/imxrt_info.html"
    result = runner.invoke(main, cmd.split())

    assert result.exit_code == 0, result.output
    assert os.path.isfile(f"{tmpdir}/imxrt_info.html")
