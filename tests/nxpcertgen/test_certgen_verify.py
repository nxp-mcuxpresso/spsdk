#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for nxpcertgen verification"""


import logging

import pytest
from click.testing import CliRunner, Result

from spsdk.apps import nxpcertgen
from spsdk.utils.misc import use_working_directory


def run_certgen_command(cmd: str, data_dir: str) -> Result:
    with use_working_directory(data_dir):
        runner = CliRunner()
        logging.debug(f"Running: {cmd}")
        result = runner.invoke(nxpcertgen.main, cmd.split())
    return result


@pytest.mark.parametrize(
    "verification_key", ["issuer_private_secp256.pem", "issuer_public_secp256.pem"]
)
def test_signature(data_dir: str, verification_key: str):
    cmd = f"verify cert_secp256.crt --sign {verification_key}"
    result = run_certgen_command(cmd, data_dir)
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "verification_key", ["subject_public_secp256.pem", "subject_private_secp256.pem"]
)
def test_puk(data_dir: str, verification_key: str):
    cmd = f"verify cert_secp256.crt --puk {verification_key}"
    result = run_certgen_command(cmd, data_dir)
    assert result.exit_code == 0


@pytest.mark.parametrize(
    "verification_key", ["subject_public_secp256.pem", "subject_private_secp256.pem"]
)
def test_signature_incorrect_key(data_dir: str, verification_key: str):
    cmd = f"verify cert_secp256.crt --sign {verification_key}"
    result = run_certgen_command(cmd, data_dir)
    assert result.exit_code != 0


@pytest.mark.parametrize(
    "verification_key", ["issuer_private_secp256.pem", "issuer_public_secp256.pem"]
)
def test_puk_incorrect_key(data_dir: str, verification_key: str):
    cmd = f"verify cert_secp256.crt --puk {verification_key}"
    result = run_certgen_command(cmd, data_dir)
    assert result.exit_code != 0


def test_incorrect_cert_format(data_dir: str):
    cmd = f"verify satyr.crt --sign subject_public_secp256.pem"
    result = run_certgen_command(cmd, data_dir)
    assert result.exit_code != 0, result.output
    assert "ECDSA" in str(result.exception)
