#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for local DICE attestation testing."""

import os
import shutil

from click.testing import CliRunner, Result

from spsdk.apps import nxpdice
from spsdk.utils.misc import use_working_directory


def run_nxpdice(command: list[str], expected_result: int) -> Result:
    runner = CliRunner()
    result = runner.invoke(nxpdice.main, command)
    assert result.exit_code == expected_result
    return result


def test_default_scenario(data_dir, tmp_path):
    models = os.path.join(data_dir, "models")
    database = os.path.join(tmp_path, "database.sqlite")
    common = ["-f", "lpc55s3x", "-p", "com90", "-md", models, "-db", database]

    with use_working_directory(tmp_path):
        cmd = ["register-ca-puk", "-r", 32 * "12", "-s", "ca_puk.bin"] + common
        run_nxpdice(cmd, expected_result=0)

        cmd = ["register-version"] + common
        run_nxpdice(cmd, expected_result=0)

        cmd = ["verify", "-s", "response.bin"] + common
        run_nxpdice(cmd, expected_result=0)


def test_upload_scenario(data_dir, tmp_path):
    database = shutil.copy(
        os.path.join(data_dir, "database.sqlite"), os.path.join(tmp_path, "database.sqlite")
    )

    cmd = ["upload-ca-puk", "-db", database, "-c", os.path.join(data_dir, "ca_puk.bin")]
    run_nxpdice(cmd, expected_result=0)

    cmd = ["upload-version", "-db", database, "-r", os.path.join(data_dir, "response.bin")]
    run_nxpdice(cmd, expected_result=0)

    cmd = ["upload-response", "-db", database, "-r", os.path.join(data_dir, "response.bin")]
    run_nxpdice(cmd, expected_result=0)
