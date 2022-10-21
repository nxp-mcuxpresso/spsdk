#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from click.testing import CliRunner

from spsdk.apps import tphost


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
