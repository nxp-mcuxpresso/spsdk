#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP DICE attestation testing module.

This module contains test cases for validating the NXP DICE (Device Identifier
Composition Engine) attestation functionality provided by the nxpdice application.
Tests cover basic attestation workflows and upload scenarios.
"""

import os
import shutil

from click.testing import CliRunner, Result

from spsdk.apps import nxpdice
from spsdk.utils.misc import use_working_directory


def run_nxpdice(command: list[str], expected_result: int) -> Result:
    """Run nxpdice CLI command and validate exit code.

    This is a test helper function that executes nxpdice CLI commands using Click's
    test runner and asserts that the command exits with the expected result code.

    :param command: List of command line arguments to pass to nxpdice.
    :param expected_result: Expected exit code from the command execution.
    :return: Click test result object containing command output and exit information.
    """
    runner = CliRunner()
    result = runner.invoke(nxpdice.main, command)
    assert result.exit_code == expected_result
    return result


def test_default_scenario(data_dir: str, tmp_path: str) -> None:
    """Test default DICE scenario with complete workflow.

    This test verifies the complete DICE (Device Identifier Composition Engine) workflow
    including CA public key registration, version registration, and verification steps
    using temporary database and working directory.

    :param data_dir: Path to directory containing test data and models.
    :param tmp_path: Temporary directory path for test execution and database storage.
    """
    models = os.path.join(data_dir, "models")
    database = os.path.join(tmp_path, "database.sqlite")
    common = ["-f", "lpc55s3x", "-p", "com90", "-md", models, "-db", database]

    with use_working_directory(tmp_path):
        cmd = ["register-ca-puk", "--rkth", 32 * "12", "-s", "ca_puk.bin"] + common
        run_nxpdice(cmd, expected_result=0)

        cmd = ["register-version"] + common
        run_nxpdice(cmd, expected_result=0)

        cmd = ["verify", "-s", "response.bin"] + common
        run_nxpdice(cmd, expected_result=0)


def test_upload_scenario(data_dir: str, tmp_path: str) -> None:
    """Test complete upload scenario for NXPDICE database operations.

    This test verifies the full workflow of uploading CA public key, version data,
    and response data to the NXPDICE database. It copies a test database to a
    temporary location and executes sequential upload commands to ensure proper
    database functionality.

    :param data_dir: Path to directory containing test data files including database.sqlite, ca_puk.bin, and response.bin
    :param tmp_path: Temporary directory path where test database will be copied for isolated testing
    """
    database = shutil.copy(
        os.path.join(data_dir, "database.sqlite"), os.path.join(tmp_path, "database.sqlite")
    )

    cmd = ["upload-ca-puk", "-db", database, "-c", os.path.join(data_dir, "ca_puk.bin")]
    run_nxpdice(cmd, expected_result=0)

    cmd = ["upload-version", "-db", database, "-r", os.path.join(data_dir, "response.bin")]
    run_nxpdice(cmd, expected_result=0)

    cmd = ["upload-response", "-db", database, "-r", os.path.join(data_dir, "response.bin")]
    run_nxpdice(cmd, expected_result=0)
