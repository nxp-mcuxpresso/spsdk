#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot test configuration and fixtures.

This module provides pytest configuration and shared fixtures for MBoot
(Master Boot) testing across the SPSDK test suite.
"""

from tests.mboot.mboot_fixtures import config  # noqa: E401, F401 # pylint: disable=unused-import
from tests.mboot.mboot_fixtures import device  # noqa: E401, F401 # pylint: disable=unused-import
from tests.mboot.mboot_fixtures import mcuboot  # noqa: E401, F401 # pylint: disable=unused-import
from tests.mboot.mboot_fixtures import target  # noqa: E401, F401 # pylint: disable=unused-import
