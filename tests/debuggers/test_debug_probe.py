#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Debug Probe interface."""
import pytest

import spsdk.debuggers.debug_probe as DP
from spsdk.exceptions import SPSDKError


def test_probe_ap_address():
    """Test of Debug Probe Interface - Test get AP index from address."""
    assert DP.DebugProbe.get_coresight_ap_address(8, 8) == 0x08000008
    with pytest.raises((SPSDKError, ValueError)):
        assert DP.DebugProbe.get_coresight_ap_address(256, 8) == 0xFF000008
