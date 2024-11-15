#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Tests for Virtual Debug Probe."""
import pytest

from spsdk.debuggers.debug_probe import (
    SPSDKDebugProbeError,
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
    virtual_probe.connect()

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
    virtual_probe.connect()

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


def test_virtualprobe_memory():
    """Test of virtual Debug Probe - Memory access tests."""
    virtual_probe = DebugProbeVirtual("ID", None)
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.mem_reg_read(0)

    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.mem_reg_write(0, 0)

    virtual_probe.open()
    virtual_probe.connect()

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


def test_virtualprobe_block_memory():
    """Test of virtual Debug Probe - Block memory access tests."""
    virtual_probe = DebugProbeVirtual("ID", None)
    virtual_probe.open()
    virtual_probe.connect()

    # Test small block write and read
    small_data = bytes([0x11, 0x22, 0x33, 0x44])
    virtual_probe.mem_block_write(0x1000, small_data)
    read_small_data = virtual_probe.mem_block_read(0x1000, len(small_data))
    assert read_small_data == small_data

    # Test large block write and read
    large_data = bytes(range(256))
    virtual_probe.mem_block_write(0x2000, large_data)
    read_large_data = virtual_probe.mem_block_read(0x2000, len(large_data))
    assert read_large_data == large_data

    # Test writing and reading across page boundaries
    cross_page_data = bytes([0xAA] * 1024)
    virtual_probe.mem_block_write(0x3FF0, cross_page_data)
    read_cross_page = virtual_probe.mem_block_read(0x3FF0, len(cross_page_data))
    assert read_cross_page == cross_page_data

    # Test reading from previously written cross-page data
    continuation_data = virtual_probe.mem_block_read(0x4000, 16)
    expected_data = bytes([0xAA] * 16)  # Continuation of the cross-page data
    assert continuation_data == expected_data

    # Test reading from truly unwritten memory
    unwritten_data = virtual_probe.mem_block_read(0x5000, 16)
    assert all(byte == 0 for byte in unwritten_data)

    # Test error handling for invalid addresses
    with pytest.raises(SPSDKDebugProbeError):
        virtual_probe.mem_block_write(0xFFFFFFFF, bytes([0x00]))

    with pytest.raises(SPSDKDebugProbeError):
        virtual_probe.mem_block_read(0xFFFFFFFF, 4)

    # Test writing and reading non-aligned addresses
    unaligned_data = bytes([0xBB] * 10)
    virtual_probe.mem_block_write(0x5003, unaligned_data)
    read_unaligned = virtual_probe.mem_block_read(0x5003, len(unaligned_data))
    assert read_unaligned == unaligned_data

    # Test overlapping writes
    virtual_probe.mem_block_write(0x6000, bytes([0xCC] * 8))
    virtual_probe.mem_block_write(0x6004, bytes([0xDD] * 8))
    overlapped_read = virtual_probe.mem_block_read(0x6000, 12)
    assert overlapped_read == bytes([0xCC] * 4 + [0xDD] * 8)
