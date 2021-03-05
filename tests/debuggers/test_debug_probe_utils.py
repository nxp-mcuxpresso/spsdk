#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Debug Probe utilities."""
import pytest

from tests.debuggers.debug_probe_virtual import DebugProbeVirtual
from spsdk.debuggers.utils import DebugProbeUtils, DebugProbes, ProbeDescription
import spsdk.debuggers.debug_probe as DP

def test_debugprobes_append():

    probe_list = DebugProbes()
    probe_descr = ProbeDescription("None", "None", "None", DP.DebugProbe)
    probe_list.append(probe_descr)

    assert probe_list.pop() == probe_descr

    with pytest.raises(TypeError):
        probe_list.append("Invalid Type")

def test_debugprobes_insert():

    probe_list = DebugProbes()
    probe_descr = ProbeDescription("None", "None", "None", DP.DebugProbe)
    probe_list.insert(0, probe_descr)

    assert probe_list.pop() == probe_descr

    with pytest.raises(TypeError):
        probe_list.insert(0, "Invalid Type")

def test_debugprobes_discovery():
    probe_list = DebugProbeUtils.get_connected_probes("virtual", DebugProbeVirtual.UNIQUE_SERIAL)

    assert probe_list.pop().description == "Special virtual debug probe used for product testing"

    probe_list = DebugProbeUtils.get_connected_probes("virtual", DebugProbeVirtual.UNIQUE_SERIAL, {"exc":None})
    assert len(probe_list) == 0

def test_debugprobes_get_probe():
    probe_list = DebugProbeUtils.get_connected_probes("virtual", DebugProbeVirtual.UNIQUE_SERIAL)

    probe = probe_list.select_probe().get_probe()
    assert isinstance(probe, DebugProbeVirtual)

    with pytest.raises(DP.DebugProbeError):
        assert probe_list.select_probe().get_probe({"exc":None}) is None
