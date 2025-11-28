#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXPImage test configuration and fixtures.

This module provides pytest configuration and shared fixtures for NXPImage
testing functionality. It sets up common test utilities and data paths
used across NXPImage test suites.
"""

import logging
import os
from typing import Any

import pytest


@pytest.fixture(scope="module")
def nxpimage_data_dir(request: Any) -> str:
    """Get nxpimage test data directory path.

    This fixture provides the path to the nxpimage test data directory by navigating
    from the current test file location to the nxpimage data folder.

    :param request: Pytest request object containing test file information.
    :return: Absolute path to the nxpimage test data directory.
    """
    logging.debug("data_dir is overloaded for module to nxpimage")
    logging.debug(f"request path {request.fspath}")
    path = os.path.dirname(request.fspath)
    path, _ = os.path.split(path)

    data_path = os.path.join(path, "nxpimage", "data")
    logging.debug(f"data_dir: {data_path}")
    return data_path
