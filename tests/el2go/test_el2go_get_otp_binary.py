#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for EL2GO get otp binary."""

import filecmp
import os

import pytest

from spsdk.apps import el2go
from tests.cli_runner import CliRunner


@pytest.mark.parametrize(
    "family, config_file, ref_binary",
    [("rw61x", "OTP_exported_configuration.json", "el2go_otp.bin")],
)
def test_el2go_otp_binary_sec_config(
    cli_runner: CliRunner, data_dir: str, tmpdir: str, family: str, config_file: str, ref_binary
) -> None:
    config = os.path.join(data_dir, config_file)
    ref_file = os.path.join(data_dir, ref_binary)
    out_file = os.path.join(tmpdir, "el2go_otp.bin")

    cmd = f"get-otp-binary -c {config} -o {out_file}"
    if family:
        cmd += f" -f {family}"

    cli_runner.invoke(el2go.main, cmd.split(), expected_code=0)
    assert os.path.isfile(out_file)
    assert filecmp.cmp(ref_file, out_file)
