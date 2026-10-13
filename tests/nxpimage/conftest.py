#!/usr/bin/env python
#
# Copyright 2022-2023,2025-2026 NXP
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

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def nxpimage_data_dir(request: Any) -> str:
    """Get nxpimage test data directory path.

    This fixture provides the path to the nxpimage test data directory by navigating
    from the current test file location to the nxpimage data folder.

    :param request: Pytest request object containing test file information.
    :return: Absolute path to the nxpimage test data directory.
    """
    logger.debug("data_dir is overloaded for module to nxpimage")
    logger.debug(f"request path {request.fspath}")
    path = os.path.dirname(request.fspath)
    path, _ = os.path.split(path)

    data_path = os.path.join(path, "nxpimage", "data")
    logger.debug(f"data_dir: {data_path}")
    return data_path
