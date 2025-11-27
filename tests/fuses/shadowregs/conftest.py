#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Shadow Registers test configuration module.

This module provides pytest configuration and fixtures for testing
Shadow Registers functionality across different debug probe configurations.
The module supports testing Shadow Registers operations with both
real hardware probes and virtual probe implementations for comprehensive
test coverage.
"""

from spsdk.debuggers.utils import PROBES
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

# Extend standard list of debug probes by virtual to allow unit testing
PROBES["virtual"] = DebugProbeVirtual
