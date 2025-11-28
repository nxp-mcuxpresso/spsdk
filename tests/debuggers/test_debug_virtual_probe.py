#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Virtual Debug Probe test module.

This module contains comprehensive test cases for the Virtual Debug Probe functionality,
covering basic operations, debug port access, memory operations, and error handling scenarios.
"""


import pytest

from spsdk.debuggers.debug_probe import (
    SPSDKDebugProbeError,
    SPSDKDebugProbeNotOpenError,
    SPSDKDebugProbeTransferError,
)
from tests.debuggers.debug_probe_virtual import DebugProbeVirtual


def test_virtualprobe_basic() -> None:
    """Test basic functionality of virtual debug probe.

    Verifies that a DebugProbeVirtual instance can be created with proper
    hardware ID assignment and that the open/close operations work correctly
    with appropriate state tracking.
    """
    virtual_probe = DebugProbeVirtual("ID", {})
    assert virtual_probe is not None
    assert virtual_probe.hardware_id == "ID"

    assert not virtual_probe.opened
    virtual_probe.open()
    assert virtual_probe.opened
    virtual_probe.close()
    assert not virtual_probe.opened


def test_virtualprobe_dp() -> None:
    """Test virtual Debug Probe debug port access functionality.

    This test verifies the virtual debug probe's coresight register read/write operations,
    error handling for unopened probes, substitute data mechanisms, and exception scenarios
    for debug port access.

    :raises SPSDKDebugProbeNotOpenError: When attempting operations on unopened probe.
    :raises SPSDKDebugProbeError: When substitute data triggers an exception.
    :raises SPSDKDebugProbeTransferError: When write operations are configured to fail.
    """
    virtual_probe = DebugProbeVirtual("ID", {})
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


def test_virtualprobe_ap() -> None:
    """Test virtual Debug Probe access port control functionality.

    Validates that the virtual debug probe correctly handles access port operations
    including error conditions when not opened, basic read/write operations,
    and substitute data functionality with various response types.

    :raises SPSDKDebugProbeNotOpenError: When attempting operations on unopened probe.
    :raises SPSDKDebugProbeError: When substitute data triggers exception response.
    """
    virtual_probe = DebugProbeVirtual("ID", {})
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


def test_virtualprobe_memory() -> None:
    """Test virtual debug probe memory access functionality.

    Validates that the virtual debug probe correctly handles memory read/write operations,
    including proper error handling when the probe is not opened, basic memory operations
    when connected, and virtual memory substitute data functionality with various data types
    and exception scenarios.

    :raises SPSDKDebugProbeNotOpenError: When attempting memory operations on unopened probe.
    :raises SPSDKDebugProbeError: When virtual memory substitute data contains exception markers.
    """
    virtual_probe = DebugProbeVirtual("ID", {})
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


def test_virtualprobe_reset() -> None:
    """Test virtual Debug Probe reset functionality.

    Verifies that the reset operation raises SPSDKDebugProbeNotOpenError when called
    on a closed probe and executes successfully when called on an open probe.

    :raises SPSDKDebugProbeNotOpenError: When reset is called on a closed probe.
    """
    virtual_probe = DebugProbeVirtual("ID", {})
    with pytest.raises(SPSDKDebugProbeNotOpenError):
        virtual_probe.reset()
    virtual_probe.open()
    virtual_probe.reset()


def test_virtualprobe_init() -> None:
    """Test virtual Debug Probe initialization functionality.

    Verifies that DebugProbeVirtual properly handles initialization with invalid
    parameters (raises SPSDKDebugProbeError) and correctly processes valid
    substitution parameters for AP, DP, and memory operations. Also tests
    the clear functionality with different parameters.

    :raises SPSDKDebugProbeError: When initialized with invalid parameters.
    """
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


def test_virtualprobe_init_false() -> None:
    """Test of virtual Debug Probe - Invalid Initialization.

    This test verifies that DebugProbeVirtual raises SPSDKDebugProbeError
    when initialized with invalid JSON format in the subs_ap parameter.

    :raises SPSDKDebugProbeError: Expected exception when invalid JSON is provided.
    """
    with pytest.raises(SPSDKDebugProbeError):
        DebugProbeVirtual("ID", {"subs_ap": '{"0":1,2]}'})


def test_virtualprobe_block_memory() -> None:
    """Test virtual Debug Probe block memory access functionality.

    Comprehensive test suite that validates the virtual debug probe's block memory
    operations including small and large data transfers, cross-page boundary handling,
    unaligned memory access, overlapping writes, error conditions, and uninitialized
    memory reads.

    :raises SPSDKDebugProbeError: When invalid memory addresses are accessed.
    """
    virtual_probe = DebugProbeVirtual("ID", {})
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
