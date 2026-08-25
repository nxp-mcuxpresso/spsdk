#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP DICE Prove Genuinity testing module.

This module contains test cases for the NXP DICE Prove Genuinity functionality,
validating both ECDSA and hybrid cryptographic response mechanisms.
"""

from spsdk.apps.nxpdice import main as nxpdice_main
from tests.cli_runner import CliRunner


def test_pg_ecdsa_response(cli_runner: CliRunner, data_dir: str) -> None:
    """Test ECDSA response for Prove Genuinity.

    This test verifies that the nxpdice CLI can successfully validate an ECDSA
    response using the verify-pg-response command with the provided response file
    and public key.

    :param cli_runner: CLI test runner for invoking commands
    :param data_dir: Directory path containing test data files
    :raises AssertionError: If the CLI command fails or returns non-zero exit code
    """

    result = cli_runner.invoke(
        nxpdice_main,
        [
            "verify-pg-response",
            "-r",
            f"{data_dir}/ecdsa_response.bin",
            "-k",
            f"{data_dir}/prod_p384.puk.bin",
        ],
    )
    assert result.exit_code == 0, f"Command failed with output: {result.output}"


def test_pg_hybrid_response(cli_runner: CliRunner, data_dir: str) -> None:
    """Test Hybrid response for Prove Genuinity.

    This test verifies that the nxpdice CLI can successfully validate a hybrid cryptographic
    response using both ML-DSA and P-384 public keys for the Prove Genuinity functionality.

    :param cli_runner: CLI test runner for invoking command line operations.
    :param data_dir: Directory path containing test data files including response and key files.
    """
    result = cli_runner.invoke(
        nxpdice_main,
        [
            "verify-pg-response",
            "-r",
            f"{data_dir}/hybrid_response.bin",
            "-k",
            f"{data_dir}/prod_hyb_mldsa.puk.bin",
            "-k",
            f"{data_dir}/prod_hyb_p384.puk.bin",
        ],
    )
    assert result.exit_code == 0, f"Command failed with output: {result.output}"
