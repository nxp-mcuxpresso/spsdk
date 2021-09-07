#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Virtual Debug Probe."""
import pytest

from spsdk.debuggers.debug_probe import (
    SPSDKDebugProbeError,
    SPSDKDebugProbeMemoryInterfaceNotEnabled,
    SPSDKDebugProbeNotOpenError,
    SPSDKDebugProbeTransferError,
)
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_virtualprobe_basic():
    """Test of virtual Debug Probe - Basic Test."""
    virtual_probe = DebugProbeVirtual("ID", None)
    assert virtual_probe is not None
    assert virtual_probe.hardware_id == "ID"

    assert not virtual_probe.opened
    virtual_probe.open()
    assert virtual_probe.opened
    virtual_probe.close()
    assert not virtual_probe.opened


def test_virtualprobe_dp():
    """Test of virtual Debug Probe - Debug port access."""
    virtual_probe = DebugProbeVirtual("ID", None)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.coresight_reg_read(False, 0)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.coresight_reg_write(False, 0, 0)
    virtual_probe.open()

    assert virtual_probe.coresight_reg_read(False, 0) == 0
    virtual_probe.coresight_reg_write(False, 0, 1)
    assert virtual_probe.coresight_reg_read(False, 0) == 1

    virtual_probe.coresight_reg_write(False, 0, 1)
    assert virtual_probe.coresight_reg_read(False, 0) == 1

    virtual_probe.set_coresight_dp_substitute_data({0: [2, 3, "Exception", "Invalid"]})
    assert virtual_probe.coresight_reg_read(False, 0) == 2
    assert virtual_probe.coresight_reg_read(False, 0) == 3
    with pytest.raises(SPSDKDebugProbeError):
        assert virtual_probe.coresight_reg_read(False, 0) == 3

    assert virtual_probe.coresight_reg_read(False, 0) == 1
    assert virtual_probe.coresight_reg_read(False, 0) == 1

    virtual_probe.dp_write_cause_exception()

    with pytest.raises(SPSDKDebugProbeTransferError):
        virtual_probe.coresight_reg_write(False, 0, 0)


def test_virtualprobe_ap():
    """Test of virtual Debug Probe - Access port control."""
    virtual_probe = DebugProbeVirtual("ID", None)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.coresight_reg_read(True, 0)

    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.coresight_reg_write(True, 0, 0)

    virtual_probe.open()

    assert virtual_probe.coresight_reg_read(True, 0) == 0
    virtual_probe.coresight_reg_write(True, 0, 1)
    assert virtual_probe.coresight_reg_read(True, 0) == 1

    virtual_probe.coresight_reg_write(True, 0, 1)
    assert virtual_probe.coresight_reg_read(True, 0) == 1

    virtual_probe.set_coresight_ap_substitute_data({0: [2, 3, "Exception", "Invalid"]})
    assert virtual_probe.coresight_reg_read(True, 0) == 2
    assert virtual_probe.coresight_reg_read(True, 0) == 3
    with pytest.raises(SPSDKDebugProbeError):
        assert virtual_probe.coresight_reg_read(True, 0) == 3
    assert virtual_probe.coresight_reg_read(True, 0) == 1
    assert virtual_probe.coresight_reg_read(True, 0) == 1


def test_virtualprobe_debugmbox():
    """Test of virtual Debug Probe - Debug mailbox API."""
    virtual_probe = DebugProbeVirtual("ID", None)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.dbgmlbx_reg_read(0)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.dbgmlbx_reg_write(0, 0)

    virtual_probe.open()

    assert virtual_probe.dbgmlbx_reg_read(0) == 0
    virtual_probe.dbgmlbx_reg_write(0, 1)
    assert virtual_probe.dbgmlbx_reg_read(0) == 1

    virtual_probe.dbgmlbx_reg_write(0, 1)
    assert virtual_probe.dbgmlbx_reg_read(0) == 1

    virtual_probe.set_coresight_ap_substitute_data({0x02000000: [2, 3]})
    assert virtual_probe.dbgmlbx_reg_read(0) == 2
    assert virtual_probe.dbgmlbx_reg_read(0) == 3
    assert virtual_probe.dbgmlbx_reg_read(0) == 1


def test_virtualprobe_memory():
    """Test of virtual Debug Probe - Memory access tests."""
    virtual_probe = DebugProbeVirtual("ID", None)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.mem_reg_read(0)

    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.mem_reg_write(0, 0)

    virtual_probe.open()
    with pytest.raises(SPSDKDebugProbeMemoryInterfaceNotEnabled):
        virtual_probe.mem_reg_read(0)
    with pytest.raises(SPSDKDebugProbeMemoryInterfaceNotEnabled):
        virtual_probe.mem_reg_write(0, 0)

    virtual_probe.enable_memory_interface()

    assert virtual_probe.mem_reg_read(0) == 0
    virtual_probe.mem_reg_write(0, 1)
    assert virtual_probe.mem_reg_read(0) == 1

    virtual_probe.mem_reg_write(0, 1)
    assert virtual_probe.mem_reg_read(0) == 1

    virtual_probe.set_virtual_memory_substitute_data({0: [2, 3, "Exception", "Invalid"]})
    assert virtual_probe.mem_reg_read(0) == 2
    assert virtual_probe.mem_reg_read(0) == 3
    with pytest.raises(SPSDKDebugProbeError):
        assert virtual_probe.mem_reg_read(0) == 3
    assert virtual_probe.mem_reg_read(0) == 1
    assert virtual_probe.mem_reg_read(0) == 1


def test_virtualprobe_reset():
    """Test of virtual Debug Probe - Reset API."""
    virtual_probe = DebugProbeVirtual("ID", None)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.reset()
    virtual_probe.open()
    virtual_probe.reset()


def test_virtualprobe_init():
    """Test of virtual Debug Probe - Initialization."""
    with pytest.raises(SPSDKDebugProbeError):
        virtual_probe = DebugProbeVirtual("ID", {"exc": None})

    virtual_probe = DebugProbeVirtual(
        "ID", {"subs_ap": '{"0":[1,2]}', "subs_dp": '{"0":[1,2]}', "subs_mem": '{"0":[1,2]}'}
    )
    assert virtual_probe.coresight_ap_substituted == {0: [2, 1]}
    assert virtual_probe.coresight_dp_substituted == {0: [2, 1]}
    assert virtual_probe.virtual_memory_substituted == {0: [2, 1]}
    virtual_probe.clear(True)
    virtual_probe.clear(False)


def test_virtualprobe_init_false():
    """Test of virtual Debug Probe - Invalid Initialization."""
    with pytest.raises(SPSDKDebugProbeError):
        DebugProbeVirtual("ID", {"subs_ap": '{"0":1,2]}'})
