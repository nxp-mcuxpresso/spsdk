#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK test configuration for debug probe testing.

This module provides pytest configuration and fixtures for testing
debug probe functionality across the SPSDK test suite. It sets up
virtual debug probes and manages probe discovery for testing purposes.
"""

from spsdk.debuggers.utils import PROBES
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

# Extend standard list of debug probes by virtual to allow unit testing
PROBES["virtual"] = DebugProbeVirtual
