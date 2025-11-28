#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK test configuration and fixtures for debug probes.

This module provides pytest configuration and shared fixtures for testing
debug probe functionality across the SPSDK debugger components without
requiring physical hardware. The module enables consistent testing of debug
probe operations by setting up virtual test infrastructure that mimics real
hardware behavior.
"""

from spsdk.debuggers.utils import PROBES
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

# Extend standard list of debug probes by virtual to allow unit testing
PROBES["virtual"] = DebugProbeVirtual
