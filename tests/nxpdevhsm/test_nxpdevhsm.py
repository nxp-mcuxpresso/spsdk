#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test some testable functionality of nxpdevhsm application."""
import os

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
from spsdk.utils.misc import load_binary, use_working_directory
from spsdk.utils.family import FamilyRevision
from tests.cli_runner import CliRunner


def test_nxpdevhsm_run_generate(cli_runner: CliRunner, data_dir, tmpdir):
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
def test_load_commands(data_dir, config, n_cmds, nf_cmds):
    """Test loading commands from SB3.1 config file."""

    with use_working_directory(data_dir):
        devhsm = DevHsmSB31.load_from_config(Config.create_from_file(config), mboot=1)
        cmds = devhsm.additional_commands
        assert len(cmds) == n_cmds

        sb3_data = SecureBinary31Commands(
            family=FamilyRevision("lpc55s3x"),
            hash_type=EnumHashAlgorithm.SHA256,
            is_encrypted=False,
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
        ("mcxa286", DevHsmSBc),
    ],
)
def test_devhsm_factory(family, expected_cls):
    """Test nxpdevhsm factory method."""
    devhsm_cls = get_devhsm_class(FamilyRevision(family))
    assert devhsm_cls == expected_cls


def test_sbx_devhsm(data_dir):
    with use_working_directory(data_dir):
        devhsm = DevHsmSBx.load_from_config(Config.create_from_file("cfg_sbx_load.yaml"), mboot=1)

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
        ("mcxa286"),
    ],
)
def test_nxpdevhsm_get_template(cli_runner: CliRunner, tmpdir, family):
    """Test NXPDEVHSM CLI - Generation IF user config."""
    cmd = ["get-template", "-f", family, "--output", f"{tmpdir}/devhsm.yml"]
    cli_runner.invoke(nxpdevhsm.main, cmd)
    assert os.path.isfile(f"{tmpdir}/devhsm.yml")


def test_devhsm_commands_are_optional(tmpdir, data_dir):
    """Test nxpdevhsm factory method."""
    config_file = "cfg_sb3_no_cmds.yaml"
    configuration = Config.create_from_file(os.path.join(data_dir, config_file))

    assert not DevHsmSB31.load_from_config(configuration, mboot=1).additional_commands
