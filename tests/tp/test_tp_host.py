#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner

from spsdk.apps import tphost
from spsdk.tp.tphost import SPSDKTpError, TrustProvisioningHost


def test_tphost_check_cot(data_dir):
    cmd = (
        f"check-cot "
        f"--root-cer {data_dir}/nxp_glob_devattest.crt "
        f"--intermediate-cert {data_dir}/lpc55_devattest.crt "
        f"--tp-response {data_dir}/wrong_tp_response.bin "
    )
    runner = CliRunner()
    result = runner.invoke(tphost.check_cot, cmd.split())
    assert result != 0


def test_tphost_with_unsupported_family():
    tp_dev = MagicMock()
    tp_dev.descriptor.get_id = MagicMock(return_value="fake-id")

    tp = TrustProvisioningHost(tpdev=tp_dev, tptarget=None, info_print=lambda x: None)
    with pytest.raises(SPSDKTpError):
        tp.load_provisioning_fw(b"", "non-existing-family")
