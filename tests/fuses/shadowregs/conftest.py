#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test module to test stuff around Shadow registers."""

from spsdk.debuggers.utils import PROBES
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual

# Extend standard list of debug probes by virtual to allow unit testing
PROBES["virtual"] = DebugProbeVirtual
