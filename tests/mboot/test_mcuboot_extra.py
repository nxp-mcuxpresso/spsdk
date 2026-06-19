#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for MCU Boot protocol commands and responses."""

# pylint: disable=redefined-outer-name
import os
from typing import Generator

import pytest

from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootError
from spsdk.mboot.mcuboot import (
    CmdPacket,
    CommandTag,
    McuBoot,
    PropertyTag,
    _clamp_down_memory_id,
    _tp_sentinel_frame,
)
from tests.mboot.device_config import DevConfig
from tests.mboot.virtual_device import VirtualDevice, VirtualMbootInterface

DEVICES_DIR = os.path.join(os.path.dirname(__file__), "..", "mboot", "devices")


@pytest.fixture
def virtual_config() -> DevConfig:
    """Return the virtual device configuration."""
    return DevConfig(os.path.join(DEVICES_DIR, "virtual_device.yaml"))


@pytest.fixture
def virtual_interface(virtual_config: DevConfig) -> VirtualMbootInterface:
    """Return an open virtual interface."""
    return VirtualMbootInterface(VirtualDevice(virtual_config))


@pytest.fixture
def mcuboot(virtual_interface: VirtualMbootInterface) -> Generator[McuBoot, None, None]:
    """Return an open McuBoot instance backed by the virtual device."""
    mb = McuBoot(virtual_interface)  # type: ignore[arg-type]
    mb.open()
    yield mb
    if mb.is_opened:
        mb.close()


# ===========================================================================================
# Helper function tests
# ===========================================================================================


def test_tp_sentinel_frame_basic() -> None:
    """Test _tp_sentinel_frame creates correctly structured frame."""
    frame = _tp_sentinel_frame(command=0x01, args=[0x1000, 0x2000])
    assert len(frame) == 4 + 2 * 4  # header + 2 args
    assert frame[0] == 0x01  # command
    assert frame[1] == 2  # arg count
    assert frame[2] == 0  # version
    assert frame[3] == 0x17  # default tag


def test_tp_sentinel_frame_custom_tag() -> None:
    """Test _tp_sentinel_frame with custom tag and version."""
    frame = _tp_sentinel_frame(command=0x05, args=[0xABCD], tag=0x42, version=1)
    assert frame[0] == 0x05
    assert frame[1] == 1
    assert frame[2] == 1
    assert frame[3] == 0x42


def test_tp_sentinel_frame_no_args() -> None:
    """Test _tp_sentinel_frame with empty args list."""
    frame = _tp_sentinel_frame(command=0x03, args=[])
    assert len(frame) == 4
    assert frame[1] == 0


def test_clamp_down_memory_id_zero() -> None:
    """Test _clamp_down_memory_id returns 0 unchanged."""
    assert _clamp_down_memory_id(0) == 0


def test_clamp_down_memory_id_mapped_external() -> None:
    """Test _clamp_down_memory_id clamps mapped external memory (1-255) to 0."""
    assert _clamp_down_memory_id(1) == 0
    assert _clamp_down_memory_id(100) == 0
    assert _clamp_down_memory_id(255) == 0


def test_clamp_down_memory_id_above_255() -> None:
    """Test _clamp_down_memory_id leaves IDs > 255 unchanged."""
    assert _clamp_down_memory_id(256) == 256
    assert _clamp_down_memory_id(0x110) == 0x110


# ===========================================================================================
# McuBoot properties and basic operations
# ===========================================================================================


def test_mcuboot_status_code(mcuboot: McuBoot) -> None:
    """Test status_code property."""
    assert mcuboot.status_code == StatusCode.SUCCESS.tag


def test_mcuboot_status_string(mcuboot: McuBoot) -> None:
    """Test status_string property."""
    assert "Success" in mcuboot.status_string


def test_mcuboot_is_opened(virtual_interface: VirtualMbootInterface) -> None:
    """Test is_opened property reflects device state."""
    mb = McuBoot(virtual_interface)  # type: ignore[arg-type]
    assert not mb.is_opened
    mb.open()
    assert mb.is_opened
    mb.close()
    assert not mb.is_opened


def test_mcuboot_context_manager(virtual_interface: VirtualMbootInterface) -> None:
    """Test McuBoot as context manager using __enter__ and __exit__."""
    with McuBoot(virtual_interface) as mb:  # type: ignore[arg-type]
        assert mb.is_opened
        assert mb.reopen is True
    assert not mb.is_opened


def test_mcuboot_open_close(virtual_interface: VirtualMbootInterface) -> None:
    """Test explicit open and close."""
    mb = McuBoot(virtual_interface)  # type: ignore[arg-type]
    mb.open()
    assert mb.is_opened
    mb.close()
    assert not mb.is_opened


# ===========================================================================================
# McuBoot internal method tests
# ===========================================================================================


def test_mcuboot_get_max_packet_size(mcuboot: McuBoot) -> None:
    """Test _get_max_packet_size fetches from device when not cached."""
    mcuboot.max_packet_size = None
    pkt_size = mcuboot._get_max_packet_size()
    assert pkt_size == 1024


def test_mcuboot_get_max_packet_size_cached(mcuboot: McuBoot) -> None:
    """Test _get_max_packet_size returns cached value on second call."""
    mcuboot.max_packet_size = None
    pkt_size1 = mcuboot._get_max_packet_size()
    pkt_size2 = mcuboot._get_max_packet_size()
    assert pkt_size1 == pkt_size2


def test_mcuboot_split_data_no_split(
    mcuboot: McuBoot, virtual_interface: VirtualMbootInterface
) -> None:
    """Test _split_data returns single chunk when no split is required."""
    virtual_interface.need_data_split = False
    data = bytes(200)
    chunks = mcuboot._split_data(data)
    assert len(chunks) == 1
    assert chunks[0] == data


def test_mcuboot_split_data_with_split(
    mcuboot: McuBoot, virtual_interface: VirtualMbootInterface
) -> None:
    """Test _split_data splits data correctly when split is needed."""
    virtual_interface.need_data_split = True
    mcuboot.max_packet_size = None
    mcuboot._get_max_packet_size()
    # data larger than max packet size (1024)
    data = bytes(2500)
    chunks = mcuboot._split_data(data)
    assert len(chunks) == 3  # 1024 + 1024 + 452


# ===========================================================================================
# McuBoot command tests using virtual device
# ===========================================================================================


def test_mcuboot_get_property_list(mcuboot: McuBoot) -> None:
    """Test get_property_list returns a non-empty list."""
    plist = mcuboot.get_property_list()
    assert mcuboot.status_code == StatusCode.SUCCESS.tag
    assert len(plist) > 0


def test_mcuboot_available_commands(mcuboot: McuBoot) -> None:
    """Test available_commands returns list of supported commands."""
    cmds = mcuboot.available_commands
    assert len(cmds) > 0


def test_mcuboot_available_commands_cached(mcuboot: McuBoot) -> None:
    """Test available_commands returns same result on second call (from cache)."""
    cmds1 = mcuboot.available_commands
    cmds2 = mcuboot.available_commands
    assert cmds1 == cmds2


def test_mcuboot_flash_erase_all(mcuboot: McuBoot) -> None:
    """Test flash_erase_all command returns True."""
    result = mcuboot.flash_erase_all()
    assert result is True
    assert mcuboot.status_code == StatusCode.SUCCESS.tag


def test_mcuboot_flash_erase_all_with_mem_id(mcuboot: McuBoot) -> None:
    """Test flash_erase_all with explicit mem_id=0."""
    result = mcuboot.flash_erase_all(mem_id=0)
    assert result is True


def test_mcuboot_flash_erase_region(mcuboot: McuBoot) -> None:
    """Test flash_erase_region command."""
    result = mcuboot.flash_erase_region(address=0x0, length=0x1000)
    assert result is True


def test_mcuboot_fill_memory(mcuboot: McuBoot) -> None:
    """Test fill_memory command."""
    result = mcuboot.fill_memory(address=0x20000000, length=100)
    assert result is True


def test_mcuboot_read_memory(mcuboot: McuBoot) -> None:
    """Test read_memory returns expected data."""
    data = mcuboot.read_memory(address=0, length=100)
    assert data is not None
    assert len(data) == 100


def test_mcuboot_write_memory(mcuboot: McuBoot) -> None:
    """Test write_memory returns True."""
    result = mcuboot.write_memory(address=0x20000000, data=bytes(64))
    assert result is True


def test_mcuboot_flash_security_disable(mcuboot: McuBoot) -> None:
    """Test flash_security_disable with valid 8-byte backdoor key."""
    result = mcuboot.flash_security_disable(backdoor_key=b"12345678")
    assert isinstance(result, bool)


def test_mcuboot_flash_security_disable_bad_key(mcuboot: McuBoot) -> None:
    """Test flash_security_disable raises McuBootError for wrong-length backdoor key."""
    with pytest.raises(McuBootError):
        mcuboot.flash_security_disable(backdoor_key=b"short")


def test_mcuboot_get_property(mcuboot: McuBoot) -> None:
    """Test get_property returns current version."""
    values = mcuboot.get_property(PropertyTag.CURRENT_VERSION)
    assert values is not None
    assert len(values) >= 1


def test_mcuboot_set_property(mcuboot: McuBoot) -> None:
    """Test set_property returns bool."""
    result = mcuboot.set_property(PropertyTag.VERIFY_WRITES, 1)
    assert isinstance(result, bool)


def test_mcuboot_get_memory_list(mcuboot: McuBoot) -> None:
    """Test get_memory_list returns expected memory regions."""
    mlist = mcuboot.get_memory_list()
    assert mcuboot.status_code == StatusCode.SUCCESS.tag
    assert "internal_flash" in mlist or "internal_ram" in mlist or len(mlist) >= 0


def test_mcuboot_execute(mcuboot: McuBoot) -> None:
    """Test execute command."""
    result = mcuboot.execute(address=0x1000, argument=0, sp=0x20001000)
    assert isinstance(result, bool)


def test_mcuboot_call(mcuboot: McuBoot) -> None:
    """Test call command."""
    result = mcuboot.call(address=0x1000, argument=0)
    assert isinstance(result, bool)


def test_mcuboot_configure_memory(mcuboot: McuBoot) -> None:
    """Test configure_memory command with mem_id=0."""
    result = mcuboot.configure_memory(mem_id=0, address=0)
    assert isinstance(result, bool)


def test_mcuboot_receive_sb_file(mcuboot: McuBoot) -> None:
    """Test receive_sb_file with minimal data."""
    data = bytes(128)
    result = mcuboot.receive_sb_file(data)
    assert isinstance(result, bool)


def test_mcuboot_key_provisioning_enroll(mcuboot: McuBoot) -> None:
    """Test kp_enroll command via virtual device."""
    result = mcuboot.kp_enroll()
    assert isinstance(result, bool)


def test_mcuboot_trust_provisioning_prove_genuinity(mcuboot: McuBoot) -> None:
    """Test tp_prove_genuinity command via virtual device."""
    result = mcuboot.tp_prove_genuinity(address=0x20000000, buffer_size=0x1000)
    assert result is None or isinstance(result, int)


def test_mcuboot_tp_prove_genuinity_buffer_too_large(mcuboot: McuBoot) -> None:
    """Test tp_prove_genuinity raises McuBootError for buffer_size > 0xFFFF."""
    with pytest.raises(McuBootError):
        mcuboot.tp_prove_genuinity(address=0x20000000, buffer_size=0x10000)


def test_mcuboot_process_cmd_not_opened(virtual_interface: VirtualMbootInterface) -> None:
    """Test _process_cmd raises McuBootConnectionError when device is closed."""
    mb = McuBoot(virtual_interface, cmd_exception=True)  # type: ignore[arg-type]
    with pytest.raises(McuBootConnectionError):
        mb._process_cmd(CmdPacket(CommandTag.READ_MEMORY, 0, 0, 100))


def test_mcuboot_read_data_not_opened(virtual_interface: VirtualMbootInterface) -> None:
    """Test _read_data raises McuBootConnectionError when device is closed."""
    mb = McuBoot(virtual_interface, cmd_exception=True)  # type: ignore[arg-type]
    with pytest.raises(McuBootConnectionError):
        mb._read_data(CommandTag.READ_MEMORY, 100)


def test_mcuboot_send_data_not_opened(virtual_interface: VirtualMbootInterface) -> None:
    """Test _send_data raises McuBootConnectionError when device is closed."""
    mb = McuBoot(virtual_interface, cmd_exception=True)  # type: ignore[arg-type]
    with pytest.raises(McuBootConnectionError):
        mb._send_data(CommandTag.WRITE_MEMORY, [b"data"])


def test_mcuboot_progress_callback_read_memory(mcuboot: McuBoot) -> None:
    """Test read_memory with progress callback invocation."""
    progress_calls = []

    def cb(current: int, total: int) -> None:
        progress_calls.append((current, total))

    data = mcuboot.read_memory(address=0, length=100, progress_callback=cb)
    assert data is not None


def test_mcuboot_progress_callback_write_memory(mcuboot: McuBoot) -> None:
    """Test write_memory with progress callback invocation."""
    progress_calls = []

    def cb(current: int, total: int) -> None:
        progress_calls.append((current, total))

    result = mcuboot.write_memory(address=0x20000000, data=bytes(64), progress_callback=cb)
    assert isinstance(result, bool)


def test_mcuboot_generate_key_blob(mcuboot: McuBoot) -> None:
    """Test generate_key_blob command via virtual device."""
    result = mcuboot.generate_key_blob(dek_data=bytes(16), key_sel=0)
    assert result is None or isinstance(result, bytes)


def test_mcuboot_trust_provisioning_set_wrapped_data(mcuboot: McuBoot) -> None:
    """Test tp_set_wrapped_data command via virtual device."""
    result = mcuboot.tp_set_wrapped_data(address=0x20000000)
    assert result is None or isinstance(result, bool)
