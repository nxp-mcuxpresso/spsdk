#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for Prove Genuinity testing."""

import pytest

from spsdk.apps.nxpdice import main as nxpdice_main
from spsdk.crypto.keys import IS_DILITHIUM_SUPPORTED
from tests.cli_runner import CliRunner


def test_pg_ecdsa_response(cli_runner: CliRunner, data_dir: str):
    """Test ECDSA response for Prove Genuinity."""

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


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed")
def test_pg_hybrid_response(cli_runner: CliRunner, data_dir: str):
    """Test Hybrid response for Prove Genuinity."""
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
