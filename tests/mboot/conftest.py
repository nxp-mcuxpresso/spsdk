#!/usr/bin/env python
#
# Copyright 2019-2022,2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot test configuration and fixtures.

This module provides pytest configuration and shared fixtures for MBoot
(Master Boot) testing across the SPSDK test suite.
"""

from tests.mboot.mboot_fixtures import config  # noqa: F401 # pylint: disable=unused-import
from tests.mboot.mboot_fixtures import device  # noqa: F401 # pylint: disable=unused-import
from tests.mboot.mboot_fixtures import mcuboot  # noqa: F401 # pylint: disable=unused-import
from tests.mboot.mboot_fixtures import target  # noqa: F401 # pylint: disable=unused-import
