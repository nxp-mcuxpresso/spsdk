#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpdebugmbox utility."""
import filecmp
import os

import pytest

from spsdk.apps.nxpdebugmbox import main
from spsdk.utils.database import get_device, get_families
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_command_line_interface_main(cli_runner: CliRunner):
    """Test for main menu options."""
    result = cli_runner.invoke(main, ["--help"])
    assert "Show this message and exit." in result.output


def get_all_devices_and_revision(feature: str, append_latest: bool = True) -> list:
    """Get list of tuples with complete device list with all revisions

    :param feature: Name of feature
    :param append_latest: Add also latest revision
    """
    ret = []
    families = get_families(feature)
    for family in families:
        device = get_device(family)
        for rev in device.revisions.revision_names(append_latest=append_latest):
            ret.append((family, rev))
    return ret


@pytest.mark.parametrize(
    "cmd",
    [
        "auth --help",
        "erase --help",
        "exit --help",
        "famode --help",
        "ispmode --help",
        "start --help",
    ],
)
def test_command_line_interface_erase(cli_runner: CliRunner, cmd):
    """Test for erase menu options."""
    result = cli_runner.invoke(main, cmd.split())
    assert "Show this message and exit." in result.output


def test_nxpdebugmbox_invalid_probe_user_param(cli_runner: CliRunner):
    """Test for Invalid debug probe user params."""
    cmd = f"-o user_par -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv start"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_nxpdebugmbox_invalid_probe(cli_runner: CliRunner):
    """Test for Invalid debug probe."""
    cmd = "-i virtual -vv start"
    cli_runner.invoke(main, cmd.split(), expected_code=1)


def test_nxpdebugmbox_valid_probe_user_param(cli_runner: CliRunner):
    """Test for Invalid debug probe user params."""
    cmd = f"-o user_par=1 -i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv start"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_start_exe(cli_runner: CliRunner):
    """Test for start command of nxp debug mailbox."""
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv start"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_exit_exe(cli_runner: CliRunner):
    """Test for exit command of nxp debug mailbox."""
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv exit"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_ispmode_exe(cli_runner: CliRunner):
    """Test for ispmode command of nxp debug mailbox."""
    hw_responses = '-o subs_ap={"33554440":[107941,0]}'
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} {hw_responses} -vv ispmode -m 0"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_famode_exe(cli_runner: CliRunner):
    """Test for famode command of nxp debug mailbox."""
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv famode"
    cli_runner.invoke(main, cmd.split())


def test_nxpdebugmbox_erase_exe(cli_runner: CliRunner):
    """Test for erase command of nxp debug mailbox."""
    cmd = f"-i virtual -s {DebugProbeVirtual.UNIQUE_SERIAL} -vv erase"
    cli_runner.invoke(main, cmd.split())


@pytest.mark.parametrize(
    "protocol",
    ["1.0", None],
)
def test_generate_rsa_dc_file(cli_runner: CliRunner, tmpdir, data_dir, protocol):
    """Test generate dc file with rsa 2048 protocol."""
    out_file = f"{tmpdir}/dc_2048.cert"
    cmd = f"gendc -c new_dck_rsa2048.yml -o {out_file}"
    if protocol:
        cmd = " ".join([f"-p {protocol}", cmd])
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


@pytest.mark.parametrize(
    "protocol",
    ["2.0", None],
)
def test_generate_ecc_dc_file(cli_runner: CliRunner, tmpdir, data_dir, protocol):
    """Test generate dc file with ecc protocol."""
    out_file = f"{tmpdir}/dc_secp256r1.cert"
    cmd = f"gendc -c new_dck_secp256.yml -o {out_file}"
    if protocol:
        cmd = " ".join([f"-p {protocol}", cmd])
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


def test_generate_dc_template(cli_runner: CliRunner, tmpdir):
    """Test generate dc file with ecc protocol for lpc55s3x"""
    out_file = f"{tmpdir}/dc_template.yaml"
    cmd = f"-f lpc55s3x get-template -o {out_file}"

    cli_runner.invoke(main, cmd.split())
    assert os.path.isfile(out_file)


def test_generate_dc_file_lpc55s3x_256(cli_runner: CliRunner, tmpdir, data_dir):
    """Test generate dc file with ecc protocol for lpc55s3x"""
    out_file = f"{tmpdir}/dc_secp256r1_lpc55s3x.cert"
    cmd = f"-p 2.0 gendc -c new_dck_secp256_lpc55s3x.yml -o {out_file}"
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


def test_generate_dc_file_mx95_a1(cli_runner: CliRunner, tmpdir, data_dir):
    """Test generate dc file with ecc protocol for mx95 a0/a1"""
    out_file = f"{tmpdir}/dc_secp256r1_mx95.cert"
    cmd = f"dat dc export -c dc_mx95_a1.yaml -o {out_file}"
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


@pytest.mark.parametrize(
    "protocol",
    ["2.1", None],
)
def test_generate_dc_file_lpc55s3x_384(cli_runner: CliRunner, tmpdir, data_dir, protocol):
    """Test generate dc file with ecc protocol for lpc55s3x"""
    out_file = f"{tmpdir}/dc_secp384r1_lpc55s3x.cert"
    cmd = f"gendc -c new_dck_secp384_lpc55s3x.yml -o {out_file}"
    if protocol:
        cmd = " ".join([f"-p {protocol}", cmd])
    with use_working_directory(data_dir):
        cli_runner.invoke(main, cmd.split())
        assert os.path.isfile(out_file)


@pytest.mark.parametrize(
    "config",
    ["elf2sb_config.yaml", "elf2sb_config_sp.yaml"],
)
def test_generate_rsa_with_elf2sb(tmpdir, data_dir, config):
    org_file = f"{tmpdir}/org.dc"
    new_file = f"{tmpdir}/new.dc"

    cmd1 = f"-p 1.0 gendc -c org_dck_rsa_2048.yml -o {org_file}"
    # keys were removed from yaml and supplied by elf2sb config
    cmd2 = f"-p 1.0 gendc -c no_key_dck_rsa_2048.yml -e elf2sb_config.yaml -o {new_file}"
    with use_working_directory(data_dir):
        result = CliRunner().invoke(main, cmd1.split())
        assert result.exit_code == 0, str(result.exception)
        result = CliRunner().invoke(main, cmd2.split())
        assert result.exit_code == 0, str(result.exception)
    assert filecmp.cmp(org_file, new_file)


@pytest.mark.parametrize(
    "family, revision",
    get_all_devices_and_revision("dat"),
)
def test_nxpdebugmbox_get_template(cli_runner: CliRunner, tmpdir, family, revision):
    """Test nxpdebugmbox CLI - Generation template."""
    cmd = ["-f", family, "-r", revision, "get-template", "--output", f"{tmpdir}/debugmbox.yml"]
    cli_runner.invoke(main, cmd)
    assert os.path.isfile(f"{tmpdir}/debugmbox.yml")


@pytest.mark.parametrize(
    "obsolete,new",
    [
        ("erase", ["cmd", "erase"]),
        ("erase-one-sector", ["cmd", "erase-one-sector"]),
        ("exit", ["cmd", "exit"]),
        ("famode", ["cmd", "famode"]),
        ("get-crp", ["cmd", "get-crp"]),
        ("ispmode", ["cmd", "ispmode"]),
        ("start", ["cmd", "start"]),
        ("start-debug-session", ["cmd", "start-debug-session"]),
        ("token_auth", ["cmd", "token-auth"]),
        ("write-to-flash", ["cmd", "write-to-flash"]),
        ("auth", ["dat", "auth"]),
        ("gendc", ["dat", "dc", "export"]),
        ("get-template", ["dat", "dc", "get-template"]),
        ("read-memory", ["mem-tool", "read-memory"]),
        ("write-memory", ["mem-tool", "write-memory"]),
        ("test-connection", ["mem-tool", "test-connection"]),
        ("get-uuid", ["tool", "get-uuid"]),
        ("reset", ["tool", "reset"]),
    ],
)
def test_obsolete_cmds(cli_runner: CliRunner, obsolete: str, new: str):
    """Test generate help for obsolete location command and new one."""
    cmd = obsolete + " --help"
    res_obsolete = cli_runner.invoke(main, cmd.split())
    res_new = cli_runner.invoke(main, new + ["--help"])
    assert "Deprecated Command" in res_obsolete.output
    assert obsolete in res_obsolete.output
    assert " ".join(new) in res_new.output
    assert res_obsolete.output.splitlines()[-1].replace(" ", "") == res_new.output.splitlines()[
        -1
    ].replace(" ", "")
