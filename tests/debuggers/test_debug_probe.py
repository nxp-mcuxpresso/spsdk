#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Debug Probe interface testing module.

This module contains unit tests for the debug probe functionality,
validating the behavior of debug probe interfaces and their methods
in the SPSDK debuggers package.
"""

import pytest

import spsdk.debuggers.debug_probe as DP
from spsdk.exceptions import SPSDKError


def test_probe_ap_address() -> None:
    """Test Debug Probe AP address calculation functionality.

    Validates that the get_coresight_ap_address method correctly calculates
    CoreSight Access Port addresses from AP index and address offset parameters.
    Also verifies proper error handling for invalid input values.

    :raises SPSDKError: When invalid AP index or address parameters are provided.
    :raises ValueError: When parameter values are out of valid range.
    """
    assert DP.DebugProbe.get_coresight_ap_address(8, 8) == 0x08000008
    with pytest.raises((SPSDKError, ValueError)):
        assert DP.DebugProbe.get_coresight_ap_address(256, 8) == 0xFF000008
