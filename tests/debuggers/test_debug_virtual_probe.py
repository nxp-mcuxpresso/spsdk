#!/usr/bin/env python
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Virtual Debug Probe test module.

This module contains comprehensive test cases for the Virtual Debug Probe functionality,
covering basic operations, debug port access, memory operations, and error handling scenarios.
"""

import pytest

from spsdk.debuggers.debug_probe import (
    MemorySpace,
    SPSDKDebugProbeError,
    SPSDKDebugProbeNotOpenError,
    SPSDKDebugProbeTransferError,
)
from tests.debuggers.debug_probe_virtual import DebugProbeDscVirtual, DebugProbeVirtual


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


# ---------------------------------------------------------------------------
# DebugProbeDscVirtual tests
# ---------------------------------------------------------------------------


def test_dsc_virtual_data_space_block_read_write() -> None:
    """Test DATA space block memory read/write via DebugProbeDscVirtual.

    Verifies that block writes and reads using the default DATA (X:) space
    round-trip correctly for typical byte counts.
    """
    probe = DebugProbeDscVirtual()

    data = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
    probe.mem_block_write(0x1000, data)
    result = probe.mem_block_read(0x1000, len(data))
    assert result == data


def test_dsc_virtual_program_space_block_read_write() -> None:
    """Test PROGRAM space block memory read/write via DebugProbeDscVirtual.

    Verifies that block writes and reads using the PROGRAM (P:) space
    round-trip correctly and do not contaminate DATA space.
    """
    probe = DebugProbeDscVirtual()

    p_data = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    probe.mem_block_write(0x2000, p_data, space=MemorySpace.PROGRAM)
    result = probe.mem_block_read(0x2000, len(p_data), space=MemorySpace.PROGRAM)
    assert result == p_data

    # DATA space at same address must still be zero
    data_result = probe.mem_block_read(0x2000, len(p_data))
    assert data_result == b"\x00" * len(p_data)


def test_dsc_virtual_data_and_program_independence() -> None:
    """Test that DATA and PROGRAM spaces are fully independent.

    Writing to DATA space must not affect PROGRAM space and vice-versa.
    """
    probe = DebugProbeDscVirtual()

    probe.mem_block_write(0x0100, bytes([0x12, 0x34]))
    probe.mem_block_write(0x0100, bytes([0x56, 0x78]), space=MemorySpace.PROGRAM)

    assert probe.mem_block_read(0x0100, 2) == bytes([0x12, 0x34])
    assert probe.mem_block_read(0x0100, 2, space=MemorySpace.PROGRAM) == bytes([0x56, 0x78])


def test_dsc_virtual_mem_reg_read_data_space() -> None:
    """Test mem_reg_read for DATA space returns a 32-bit value from two consecutive words."""
    probe = DebugProbeDscVirtual()

    # Store low word at addr, high word at addr+1
    probe.data_memory[0x0010] = 0xCDEF  # low
    probe.data_memory[0x0011] = 0xAB12  # high

    value = probe.mem_reg_read(0x0010, space=MemorySpace.DATA)
    assert value == 0xAB12CDEF


def test_dsc_virtual_mem_reg_read_program_space() -> None:
    """Test mem_reg_read for PROGRAM space returns the 16-bit word at the given address."""
    probe = DebugProbeDscVirtual()

    probe.program_memory[0x0020] = 0xBEEF

    value = probe.mem_reg_read(0x0020, space=MemorySpace.PROGRAM)
    assert value == 0xBEEF
    # Upper 16 bits must be zero for PROGRAM space
    assert value & 0xFFFF0000 == 0


def test_dsc_virtual_mem_reg_write_data_space() -> None:
    """Test mem_reg_write for DATA space stores two 16-bit words correctly."""
    probe = DebugProbeDscVirtual()

    probe.mem_reg_write(0x0030, 0xDEADBEEF, space=MemorySpace.DATA)

    assert probe.data_memory[0x0030] == 0xBEEF
    assert probe.data_memory[0x0031] == 0xDEAD


def test_dsc_virtual_mem_reg_write_program_space() -> None:
    """Test mem_reg_write for PROGRAM space stores only the lower 16-bit word."""
    probe = DebugProbeDscVirtual()

    probe.mem_reg_write(0x0040, 0x00001234, space=MemorySpace.PROGRAM)

    assert probe.program_memory[0x0040] == 0x1234
    # DATA space at same address must be unaffected
    assert 0x0040 not in probe.data_memory


def test_dsc_virtual_program_space_backward_compat_default() -> None:
    """Test that calling mem_block_read/write without space defaults to DATA space."""
    probe = DebugProbeDscVirtual()

    probe.mem_block_write(0x0050, bytes([0x11, 0x22, 0x33, 0x44]))
    result = probe.mem_block_read(0x0050, 4)
    assert result == bytes([0x11, 0x22, 0x33, 0x44])

    # PROGRAM space at same address must still be empty
    assert 0x0050 not in probe.program_memory


def test_dsc_virtual_enum_labels() -> None:
    """Test DscMemorySpace enum has expected labels for Click CLI integration."""
    labels = MemorySpace.labels()
    assert "data" in labels
    assert "program" in labels
    assert MemorySpace.from_label("data") == MemorySpace.DATA
    assert MemorySpace.from_label("program") == MemorySpace.PROGRAM


def test_dsc_virtual_odd_byte_count_program_space() -> None:
    """Test that an odd byte count is handled correctly in PROGRAM space block ops."""
    probe = DebugProbeDscVirtual()

    # 3-byte write: should be padded to 2 words (4 bytes); read back 3 bytes
    probe.mem_block_write(0x0060, bytes([0xAA, 0xBB, 0xCC]), space=MemorySpace.PROGRAM)
    result = probe.mem_block_read(0x0060, 3, space=MemorySpace.PROGRAM)
    assert result == bytes([0xAA, 0xBB, 0xCC])
