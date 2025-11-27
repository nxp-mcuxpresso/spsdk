#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK nxpdevhsm application functionality.

This module contains comprehensive unit tests for the nxpdevhsm application,
which provides secure provisioning capabilities for NXP development HSM devices.
Tests cover command generation, template handling, device factory operations,
and SBX device integration.
"""

import os
from typing import Any

import pytest

from spsdk.apps import nxpdevhsm
from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.sbfile.devhsm.utils import get_devhsm_class
from spsdk.sbfile.sb31.commands import CmdLoadKeyBlob
from spsdk.sbfile.sb31.devhsm import DevHsmSB31
from spsdk.sbfile.sb31.images import SecureBinary31Commands
from spsdk.sbfile.sbc.devhsm import DevHsmSBc
from spsdk.sbfile.sbx.devhsm import DevHsmSBx
from spsdk.sbfile.sbx.images import SecureBinaryXType
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import load_binary, use_working_directory
from tests.cli_runner import CliRunner


def test_nxpdevhsm_run_generate(cli_runner: CliRunner, data_dir: str, tmpdir: Any) -> None:
    """Test nxpdevhsm CLI generate command with invalid COM port.

    This test verifies that the nxpdevhsm generate command properly handles
    the case when an invalid or non-existent COM port is specified. It expects
    the command to fail with a specific error message indicating no devices
    were found for the given UART interface parameters.

    :param cli_runner: Click CLI test runner for invoking commands.
    :param data_dir: Directory containing test data files.
    :param tmpdir: Temporary directory for test output files.
    """
    with use_working_directory(data_dir):
        cmd = (
            "generate -p COMx "
            "-oc family=lpc55s3x "
            "-oc containerKeyBlobEncryptionKey=test_bin.bin "
            "-oc oemRandomShare=test_bin.bin "
            f"-oc containerOutputFile={tmpdir}/bootable_images/cust_mk_sk.sb"
        )
        result = cli_runner.invoke(nxpdevhsm.main, cmd.split(), expected_code=1)
        assert (
            "No devices for given interface 'uart' and parameters 'port=COMx, timeout=5000' was found."
            == str(result.exception)
        )


@pytest.mark.parametrize(
    "config,n_cmds,nf_cmds",
    [
        ("cfg_sb3_load.yaml", 1, 2),
        ("cfg_sb3_keyblob.yaml", 2, 3),
    ],
)
def test_load_commands(data_dir: str, config: str, n_cmds: int, nf_cmds: int) -> None:
    """Test loading commands from SB3.1 config file.

    This test verifies that commands can be properly loaded from a configuration file,
    added to a SecureBinary31Commands object, and processed correctly. It checks that
    the expected number of commands are loaded and that the final processed data
    contains the expected binary content.

    :param data_dir: Directory path containing test data files.
    :param config: Path to the SB3.1 configuration file to load.
    :param n_cmds: Expected number of additional commands to be loaded.
    :param nf_cmds: Expected total number of commands after adding all commands.
    """

    with use_working_directory(data_dir):
        devhsm = DevHsmSB31.load_from_config(Config.create_from_file(config), mboot=1)  # type: ignore
        cmds = devhsm.additional_commands
        assert cmds is not None
        assert len(cmds) == n_cmds

        sb3_data = SecureBinary31Commands(
            family=FamilyRevision("lpc55s3x"), hash_type=EnumHashAlgorithm.SHA256
        )
        sb3_data.add_command(
            CmdLoadKeyBlob(
                offset=0x04,
                data=b"0123456789012345",
                key_wrap_id=CmdLoadKeyBlob.get_key_id(
                    family=FamilyRevision("lpc55s3x"),
                    key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK,
                ),
            )
        )
        for cmd in cmds:
            sb3_data.add_command(cmd)

        assert len(sb3_data.commands) == nf_cmds
        cmd_blocks = sb3_data.get_cmd_blocks_to_export()
        processed = sb3_data.process_cmd_blocks_to_export(cmd_blocks)
        assert load_binary("test_bin.bin") in processed


@pytest.mark.parametrize(
    "family,expected_cls",
    [
        ("lpc55s3x", DevHsmSB31),
        ("mc56f818xx", DevHsmSBx),
        ("mcxa366", DevHsmSBc),
    ],
)
def test_devhsm_factory(family: str, expected_cls: Any) -> None:
    """Test nxpdevhsm factory method.

    Verifies that the get_devhsm_class factory function returns the correct
    DevHSM class for a given family revision.

    :param family: The family name to test with the factory method.
    :param expected_cls: The expected DevHSM class that should be returned by the factory.
    """
    devhsm_cls = get_devhsm_class(FamilyRevision(family))
    assert devhsm_cls == expected_cls


def test_sbx_devhsm(data_dir: str) -> None:
    """Test SBx DevHSM functionality with configuration file.

    This test verifies that the DevHsmSBx class can properly load from a YAML
    configuration file and validates the resulting secure binary properties
    including commands, image type, signing status, and block size.

    :param data_dir: Directory path containing test data and configuration files
    """
    with use_working_directory(data_dir):
        devhsm = DevHsmSBx.load_from_config(Config.create_from_file("cfg_sbx_load.yaml"), mboot=1)  # type: ignore

    assert "ERASE: Address=0x00000000, Length=4096, Memory ID=0\n" in str(devhsm.sbx.sb_commands)
    assert devhsm.sbx.image_type == SecureBinaryXType.OEM_PROVISIONING
    assert not devhsm.sbx.isk_signed
    assert devhsm.sbx.sb_header.block_size == 292


@pytest.mark.parametrize(
    "family",
    [
        ("lpc55s3x"),
        ("mc56f818xx"),
        ("mcxn9xx"),
        ("mwct20d2"),
        ("rw61x"),
        ("mcxa255"),
        ("mcxa256"),
        ("mcxa366"),
        ("mcxa365"),
    ],
)
def test_nxpdevhsm_get_template(cli_runner: CliRunner, tmpdir: Any, family: str) -> None:
    """Test NXPDEVHSM CLI get-template command functionality.

    Verifies that the get-template command generates a valid configuration file
    for the specified device family and saves it to the expected output location.

    :param cli_runner: Click CLI test runner for invoking commands
    :param tmpdir: Temporary directory fixture for test file operations
    :param family: Device family name to generate template for
    :raises AssertionError: If the generated configuration file does not exist
    """
    cmd = ["get-template", "-f", family, "--output", f"{tmpdir}/devhsm.yml"]
    cli_runner.invoke(nxpdevhsm.main, cmd)
    assert os.path.isfile(f"{tmpdir}/devhsm.yml")


def test_devhsm_commands_are_optional(tmpdir: Any, data_dir: str) -> None:
    """Test that DevHSM commands are optional in configuration.

    Verifies that the DevHsmSB31 factory method correctly handles configurations
    without additional commands, ensuring the additional_commands attribute is empty
    when no commands are specified in the configuration file.

    :param tmpdir: Temporary directory for test files (unused in this test).
    :param data_dir: Path to the directory containing test data files.
    """
    config_file = "cfg_sb3_no_cmds.yaml"
    configuration = Config.create_from_file(os.path.join(data_dir, config_file))

    assert not DevHsmSB31.load_from_config(configuration, mboot=1).additional_commands  # type: ignore
