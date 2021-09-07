#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Debug Probe interface."""
import pytest

import spsdk
import spsdk.debuggers.debug_probe as DP


def test_probe_ap_address():
    """Test of Debug Probe Interface - Test get AP index from address."""
    assert DP.DebugProbe.get_coresight_ap_address(8, 8) == 0x08000008
    with pytest.raises((spsdk.SPSDKError, ValueError)):
        assert DP.DebugProbe.get_coresight_ap_address(256, 8) == 0xFF000008


def test_probe_get_connected_probes():
    """Test of Debug Probe Interface - Test getting of connected probes."""
    with pytest.raises(NotImplementedError):
        DP.DebugProbe.get_connected_probes()


def test_probe_not_implemented():
    """Test of Debug Probe Interface - Test of none implemented API."""
    probe = DP.DebugProbe("ID", None)
    with pytest.raises(NotImplementedError):
        probe.get_connected_probes()

    assert probe.debug_mailbox_access_port == -1
    probe.debug_mailbox_access_port = 10
    assert probe.debug_mailbox_access_port == 10

    with pytest.raises(NotImplementedError):
        probe.open()

    probe.enable_memory_interface()

    with pytest.raises(NotImplementedError):
        probe.close()

    with pytest.raises(NotImplementedError):
        probe.dbgmlbx_reg_read()

    with pytest.raises(NotImplementedError):
        probe.dbgmlbx_reg_write()

    with pytest.raises(NotImplementedError):
        probe.mem_reg_read()

    with pytest.raises(NotImplementedError):
        probe.mem_reg_write()

    with pytest.raises(NotImplementedError):
        probe.coresight_reg_read()

    with pytest.raises(NotImplementedError):
        probe.coresight_reg_write()

    with pytest.raises(NotImplementedError):
        probe.reset()
