#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Virtual Debug Probe."""
import pytest

from spsdk.debuggers.debug_probe import (
    DebugProbeError,
    DebugProbeNotOpenError,
    DebugProbeMemoryInterfaceNotEnabled,
    DebugProbeTransferError
    )
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_virtualprobe_basic():
    vp = DebugProbeVirtual("ID", None)
    assert vp is not None
    assert vp.hardware_id == "ID"

    assert not vp.opened
    vp.open()
    assert vp.opened
    vp.close()
    assert not vp.opened

def test_virtualprobe_dp():
    vp = DebugProbeVirtual("ID", None)
    with pytest.raises(DebugProbeNotOpenError):
        vp.coresight_reg_read(False, 0)
    with pytest.raises(DebugProbeNotOpenError):
        vp.coresight_reg_write(False, 0, 0)
    vp.open()

    assert vp.coresight_reg_read(False, 0) == 0
    vp.coresight_reg_write(False, 0, 1)
    assert vp.coresight_reg_read(False, 0) == 1

    vp.coresight_reg_write(False, 0, 1)
    assert vp.coresight_reg_read(False, 0) == 1

    vp.set_coresight_dp_substitute_data({0:[2, 3, "Exception", "Invalid"]})
    assert vp.coresight_reg_read(False, 0) == 2
    assert vp.coresight_reg_read(False, 0) == 3
    with pytest.raises(DebugProbeError):
        assert vp.coresight_reg_read(False, 0) == 3

    assert vp.coresight_reg_read(False, 0) == 1
    assert vp.coresight_reg_read(False, 0) == 1

    vp.dp_write_cause_exception()

    with pytest.raises(DebugProbeTransferError):
        vp.coresight_reg_write(False, 0, 0)

def test_virtualprobe_ap():
    vp = DebugProbeVirtual("ID", None)
    with pytest.raises(DebugProbeNotOpenError):
        vp.coresight_reg_read(True, 0)

    with pytest.raises(DebugProbeNotOpenError):
        vp.coresight_reg_write(True, 0, 0)

    vp.open()

    assert vp.coresight_reg_read(True, 0) == 0
    vp.coresight_reg_write(True, 0, 1)
    assert vp.coresight_reg_read(True, 0) == 1

    vp.coresight_reg_write(True, 0, 1)
    assert vp.coresight_reg_read(True, 0) == 1

    vp.set_coresight_ap_substitute_data({0:[2, 3, "Exception", "Invalid"]})
    assert vp.coresight_reg_read(True, 0) == 2
    assert vp.coresight_reg_read(True, 0) == 3
    with pytest.raises(DebugProbeError):
        assert vp.coresight_reg_read(True, 0) == 3
    assert vp.coresight_reg_read(True, 0) == 1
    assert vp.coresight_reg_read(True, 0) == 1

def test_virtualprobe_debugmbox():
    vp = DebugProbeVirtual("ID", None)
    with pytest.raises(DebugProbeNotOpenError):
        vp.dbgmlbx_reg_read(0)
    with pytest.raises(DebugProbeNotOpenError):
        vp.dbgmlbx_reg_write(0, 0)

    vp.open()

    assert vp.dbgmlbx_reg_read(0) == 0
    vp.dbgmlbx_reg_write(0, 1)
    assert vp.dbgmlbx_reg_read(0) == 1

    vp.dbgmlbx_reg_write(0, 1)
    assert vp.dbgmlbx_reg_read(0) == 1

    vp.set_coresight_ap_substitute_data({0x02000000:[2, 3]})
    assert vp.dbgmlbx_reg_read(0) == 2
    assert vp.dbgmlbx_reg_read(0) == 3
    assert vp.dbgmlbx_reg_read(0) == 1

def test_virtualprobe_memory():
    vp = DebugProbeVirtual("ID", None)
    with pytest.raises(DebugProbeNotOpenError):
        vp.mem_reg_read(0)

    with pytest.raises(DebugProbeNotOpenError):
        vp.mem_reg_write(0, 0)

    vp.open()
    with pytest.raises(DebugProbeMemoryInterfaceNotEnabled):
        vp.mem_reg_read(0)
    with pytest.raises(DebugProbeMemoryInterfaceNotEnabled):
        vp.mem_reg_write(0, 0)

    vp.enable_memory_interface()

    assert vp.mem_reg_read(0) == 0
    vp.mem_reg_write(0, 1)
    assert vp.mem_reg_read(0) == 1

    vp.mem_reg_write(0, 1)
    assert vp.mem_reg_read(0) == 1

    vp.set_virtual_memory_substitute_data({0:[2, 3, "Exception", "Invalid"]})
    assert vp.mem_reg_read(0) == 2
    assert vp.mem_reg_read(0) == 3
    with pytest.raises(DebugProbeError):
        assert vp.mem_reg_read(0) == 3
    assert vp.mem_reg_read(0) == 1
    assert vp.mem_reg_read(0) == 1

def test_virtualprobe_reset():
    vp = DebugProbeVirtual("ID", None)
    with pytest.raises(DebugProbeNotOpenError):
        vp.reset()
    vp.open()
    vp.reset()

def test_virtualprobe_init():
    with pytest.raises(DebugProbeError):
        vp = DebugProbeVirtual("ID", {"exc":None})

    vp = DebugProbeVirtual("ID", {"subs_ap":'{"0":[1,2]}', "subs_dp":'{"0":[1,2]}', "subs_mem":'{"0":[1,2]}'})
    assert vp.coresight_ap_substituted == {0:[2, 1]}
    assert vp.coresight_dp_substituted == {0:[2, 1]}
    assert vp.virtual_memory_substituted == {0:[2, 1]}
    vp.clear(True)
    vp.clear(False)

def test_virtualprobe_init_false():
    with pytest.raises(DebugProbeError):
        DebugProbeVirtual("ID", {"subs_ap":'{"0":1,2]}'})
