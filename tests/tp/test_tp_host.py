#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from unittest.mock import MagicMock

import pytest

from spsdk.apps import tphost
from spsdk.tp.tphost import TrustProvisioningHost
from spsdk.utils.database import SPSDKErrorMissingDevice
from tests.cli_runner import CliRunner


def test_tphost_check_cot(cli_runner: CliRunner, data_dir):
    cmd = [
        "--root-cert",
        f"{data_dir}/nxp_glob_devattest.crt",
        "--intermediate-cert",
        f"{data_dir}/lpc55_devattest.crt",
        "--tp-response",
        f"{data_dir}/tp_response.bin",
    ]
    result = cli_runner.invoke(tphost.check_cot, cmd, expected_code=-1)
    assert "OK" in result.output
    assert "FAILED" in result.output


def test_tphost_check_cot_no_glob(cli_runner: CliRunner, data_dir):
    cmd = [
        "--intermediate-cert",
        f"{data_dir}/lpc55_devattest.crt",
        "--tp-response",
        f"{data_dir}/tp_response.bin",
    ]
    result = cli_runner.invoke(tphost.check_cot, cmd, expected_code=-1)
    assert "OK" in result.output
    assert "FAILED" in result.output


def test_tphost_check_cot_no_glob_bin(cli_runner: CliRunner, data_dir):
    cmd = [
        "--intermediate-cert",
        f"{data_dir}/lpc55_devattest.bin",
        "--tp-response",
        f"{data_dir}/tp_response.bin",
    ]
    result = cli_runner.invoke(tphost.check_cot, cmd, expected_code=-1)
    assert "OK" in result.output
    assert "FAILED" in result.output


def test_tphost_with_unsupported_family():
    tp_dev = MagicMock()
    tp_dev.descriptor.get_id = MagicMock(return_value="fake-id")

    tp = TrustProvisioningHost(tpdev=tp_dev, tptarget=None, info_print=lambda x: None)
    with pytest.raises(SPSDKErrorMissingDevice):
        tp.load_provisioning_fw(b"", "non-existing-family")
