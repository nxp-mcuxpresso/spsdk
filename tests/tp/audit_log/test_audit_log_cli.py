#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest
from click.testing import CliRunner

from spsdk.apps import tphost


def test_cli_run(data_dir):

    cmd = (
        f"verify --audit-log {data_dir}/tp_audit_log.db "
        f"--audit-log-key {data_dir}/oem_log_puk.pub"
    )

    runner = CliRunner()
    result = runner.invoke(tphost.main, cmd.split())
    assert result.exit_code == 0


# The sample audit log file contains 4 devices, 4 OEM + 1 NXP cert for each device
@pytest.mark.parametrize(
    "skip_nxp, skip_oem, cert_index, expected_count",
    [
        (False, False, None, 20),  # (4+1) x 4
        (False, True, None, 4),  # only 4 NXP devices
        (True, False, None, 16),  # 4 x 4 OEM certs
        (False, False, 2, 8),  # 4 NXP + 4 OEM certs #2
        (False, True, 2, 4),  # 4 OEM certs #2
        (True, False, 3, 4),  # 4 NXP certs (cert selector has no impact)
    ],
)
def test_tphost_extract(data_dir, tmpdir, skip_nxp, skip_oem, cert_index, expected_count):

    cmd = (
        f"verify --audit-log {data_dir}/tp_audit_log.db "
        f"--audit-log-key {data_dir}/oem_log_puk.pub --destination {tmpdir}"
    )
    if skip_nxp:
        cmd += " --skip-nxp"
    if skip_oem:
        cmd += " --skip-oem"
    if cert_index:
        cmd += f" --cert-index {cert_index}"

    runner = CliRunner()
    result = runner.invoke(tphost.main, cmd.split())
    assert result.exit_code == 0
    assert len(os.listdir(tmpdir)) == expected_count
