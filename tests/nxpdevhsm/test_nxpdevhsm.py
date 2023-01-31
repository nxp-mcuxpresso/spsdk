#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test some testable functionality of nxpdevhsm application."""
import pytest
from click.testing import CliRunner

from spsdk.apps import nxpdevhsm
from spsdk.apps.nxpdevhsm import DeviceHsm
from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb31.commands import CmdLoadKeyBlob
from spsdk.sbfile.sb31.images import SecureBinary31Commands
from spsdk.utils.misc import load_binary, use_working_directory


def test_nxpdevhsm_run_generate(data_dir, tmpdir):
    runner = CliRunner()
    with use_working_directory(data_dir):

        cmd = f"generate -p COMx -f lpc55s3x -k test_bin.bin -o test_bin.bin {tmpdir}/bootable_images/cust_mk_sk.sb"
        result = runner.invoke(nxpdevhsm.main, cmd.split())
        assert result.exit_code == 1
        assert "COMx" in result.exception.description


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
        devhsm = DeviceHsm(
            mboot=None,
            user_pck=b"abcd",
            oem_share_input=b"abcd",
            info_print=None,
            container_conf=config,
            family="lpc55s3x",
        )
        cmds = devhsm.get_cmd_from_config()
        assert len(cmds) == n_cmds

        sb3_data = SecureBinary31Commands(
            family="lpc55s3x", curve_name="secp256r1", is_encrypted=False
        )
        sb3_data.add_command(
            CmdLoadKeyBlob(
                offset=0x04,
                data=b"0123456789012345",
                key_wrap_id=CmdLoadKeyBlob.get_key_id(
                    family="lpc55s3x", key_name=CmdLoadKeyBlob.KeyTypes.NXP_CUST_KEK_EXT_SK
                ),
            )
        )
        sb3_data.load_from_config(cmds)

        assert len(sb3_data.commands) == nf_cmds
        cmd_blocks = sb3_data.get_cmd_blocks_to_export()
        processed = sb3_data.process_cmd_blocks_to_export(cmd_blocks)
        assert load_binary("test_bin.bin") in processed


def test_load_commands_with_keyblob4(data_dir):
    """Test loading commands from SB3.1 config file."""

    with use_working_directory(data_dir):
        with pytest.raises(SPSDKError):
            devhsm = DeviceHsm(
                mboot=None,
                user_pck=b"abcd",
                oem_share_input=b"abcd",
                info_print=None,
                container_conf="cfg_sb3_keyblob4.yaml",
                family="lpc55s3x",
            )
            devhsm.get_cmd_from_config()
