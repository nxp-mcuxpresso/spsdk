#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpcertgen verification"""


import logging

import pytest
from click.testing import Result

from spsdk.apps import nxpcertgen
from spsdk.utils.misc import use_working_directory
from tests.cli_runner import CliRunner


def run_certgen_command(cli_runner: CliRunner, cmd: str, data_dir: str, expected_code=0) -> Result:
    with use_working_directory(data_dir):
        logging.debug(f"Running: {cmd}")
        result = cli_runner.invoke(nxpcertgen.main, cmd.split(), expected_code=expected_code)
    return result


@pytest.mark.parametrize(
    "verification_key", ["issuer_private_secp256.pem", "issuer_public_secp256.pem"]
)
def test_signature(cli_runner: CliRunner, data_dir: str, verification_key: str):
    cmd = f"verify -c cert_secp256.crt --sign {verification_key}"
    run_certgen_command(cli_runner, cmd, data_dir)


@pytest.mark.parametrize(
    "verification_key", ["subject_public_secp256.pem", "subject_private_secp256.pem"]
)
def test_puk(cli_runner: CliRunner, data_dir: str, verification_key: str):
    cmd = f"verify -c cert_secp256.crt --puk {verification_key}"
    run_certgen_command(cli_runner, cmd, data_dir)


@pytest.mark.parametrize(
    "verification_key", ["subject_public_secp256.pem", "subject_private_secp256.pem"]
)
def test_signature_incorrect_key(cli_runner: CliRunner, data_dir: str, verification_key: str):
    cmd = f"verify -c cert_secp256.crt --sign {verification_key}"
    run_certgen_command(cli_runner, cmd, data_dir, expected_code=-1)


@pytest.mark.parametrize(
    "verification_key", ["issuer_private_secp256.pem", "issuer_public_secp256.pem"]
)
def test_puk_incorrect_key(cli_runner: CliRunner, data_dir: str, verification_key: str):
    cmd = f"verify -c cert_secp256.crt --puk {verification_key}"
    result = run_certgen_command(cli_runner, cmd, data_dir, expected_code=-1)


def test_incorrect_cert_format(cli_runner: CliRunner, data_dir: str):
    cmd = "verify -c satyr.crt --sign subject_public_secp256.pem"
    result = run_certgen_command(cli_runner, cmd, data_dir, expected_code=-1)
    assert "ECDSA" in str(result.exception)
