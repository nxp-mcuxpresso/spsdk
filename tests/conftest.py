#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import logging
from os import environ, path

import pytest
from cryptography.hazmat.backends.openssl import backend

from tests.cli_runner import CliRunner

# Disable RSA key blinding to speed up unit tests in cryptography 37+
# https://github.com/pyca/cryptography/issues/7236
backend._rsa_skip_check_key = True

# Skip test collection of TP tests if smartcard package cannot be imported
try:
    import smartcard
except ImportError:
    collect_ignore_glob = ["tp*"]

environ["SPSDK_ENV_CACHE_DISABLED"] = "False"


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture(scope="module")
def data_dir(request):
    logging.debug(f"data_dir for module: {request.fspath}")
    data_path = path.join(path.dirname(request.fspath), "data")
    logging.debug(f"data_dir: {data_path}")
    return data_path


def pytest_addoption(parser):
    parser.addoption(
        "--target",
        action="store",
        default="VIRTUAL",
        help="Device: VIRTUAL, IMXRT, ... or 'VID:PID'",
    )
