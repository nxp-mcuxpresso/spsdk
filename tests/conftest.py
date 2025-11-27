#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK pytest configuration and shared test fixtures.

This module provides pytest configuration options and commonly used
test fixtures for the SPSDK test suite. It defines shared fixtures
that can be used across multiple test modules to ensure consistent
testing environment and utilities.
"""

import logging
import os
from typing import Any

import pytest
from cryptography.hazmat.backends.openssl import backend

from tests.cli_runner import CliRunner

# Disable RSA key blinding to speed up unit tests in cryptography 37+
# https://github.com/pyca/cryptography/issues/7236
setattr(backend, "_rsa_skip_check_key", True)

os.environ["SPSDK_ENV_CACHE_DISABLED"] = "False"
os.environ["SPSDK_DEBUG_LOGGING_DISABLED"] = "True"


@pytest.fixture
def cli_runner() -> CliRunner:
    """Get CLI runner instance for testing.

    Creates and returns a Click CliRunner instance that can be used to invoke
    command-line interface commands in tests.

    :return: CliRunner instance for testing CLI commands.
    """
    return CliRunner()


@pytest.fixture(scope="module")
def data_dir(request: Any) -> str:
    """Get test data directory path for the current test module.

    Constructs the absolute path to the 'data' directory located alongside
    the test file that is currently being executed.

    :param request: Pytest request fixture containing test execution context.
    :return: Absolute path to the test data directory.
    """
    logging.debug(f"data_dir for module: {request.fspath}")
    data_path = os.path.join(os.path.dirname(request.fspath), "data")
    logging.debug(f"data_dir: {data_path}")
    return data_path


@pytest.fixture
def tests_root_dir() -> str:
    """Get the root directory of tests.

    Returns the absolute path to the directory containing the test files.

    :return: Absolute path to the tests root directory.
    """
    return os.path.dirname(os.path.abspath(__file__))


def pytest_addoption(parser: Any) -> None:
    """Add pytest command line options for SPSDK tests.

    This function configures pytest to accept additional command line arguments
    specific to SPSDK testing, particularly for specifying target devices.

    :param parser: Pytest argument parser for adding custom command line options
    :raises: No exceptions are explicitly raised by this function
    """
    parser.addoption(
        "--target",
        action="store",
        default="VIRTUAL",
        help="Device: VIRTUAL, IMXRT, ... or 'VID:PID'",
    )
