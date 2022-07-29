#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk import SPSDKError
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootCommandError, McuBootConnectionError, McuBootError
from spsdk.mboot.mcuboot import (
    CmdPacket,
    CommandTag,
    ExtMemId,
    KeyProvUserKeyType,
    McuBoot,
    PropertyTag,
    StatusCode,
)
from tests.mcu_examples.test_rt5xx import write_shadow_regis


def test_class(mcuboot, target, config):
    assert mcuboot.is_opened
    mcuboot.close()
    with pytest.raises(McuBootConnectionError):
        mcuboot._process_cmd(CmdPacket(CommandTag.READ_MEMORY, 0, 0, 1000))
    with pytest.raises(McuBootConnectionError):
        mcuboot._read_data(CommandTag.READ_MEMORY, 1000)
    with pytest.raises(McuBootConnectionError):
        mcuboot._send_data(CommandTag.WRITE_MEMORY, [b"00000000"])
    assert not mcuboot.is_opened
    mcuboot.open()


def test_cmd_get_property_list(mcuboot, target, config):
    plist = mcuboot.get_property_list()
    assert mcuboot.status_code == StatusCode.SUCCESS
    assert len(plist) == config.get_properties_count()


def test_cmd_get_memory_list(mcuboot, target):
    mlist = mcuboot.get_memory_list()
    assert mcuboot.status_code == StatusCode.SUCCESS
    assert len(mlist) == 2


def test_cmd_read_memory(mcuboot, target):
    data = mcuboot.read_memory(0, 1000)
    assert mcuboot.status_code == StatusCode.SUCCESS
    assert data is not None
    assert len(data) == 1000


def test_cmd_read_memory_callback(mcuboot, target):
    iteration_counter = 0

    def callback(transferred: int, total: int) -> None:
        nonlocal iteration_counter
        iteration_counter += 1
        # NOTE: in our simulation read_memory always returns 1024B :(
        assert transferred >= 500
        assert total == 500

    data = mcuboot.read_memory(0, 500, progress_callback=callback)
    # TODO: currently we can test only single iteration
    assert iteration_counter == 1


def test_cmd_read_memory_data_abort(mcuboot, target):
    mcuboot._device.fail_step = StatusCode.FLASH_OUT_OF_DATE_CFPA_PAGE
    mcuboot.read_memory(0, 1000)
    assert mcuboot.status_code == StatusCode.FLASH_OUT_OF_DATE_CFPA_PAGE


def test_cmd_read_memory_timeout(mcuboot, target):
    mcuboot._device.fail_step = 0
    mcuboot.read_memory(0, 100)
    assert mcuboot.status_code == StatusCode.NO_RESPONSE

    mcuboot._cmd_exception = True
    with pytest.raises(McuBootCommandError) as exc_info:
        mcuboot.read_memory(0, 100)
    mcuboot._cmd_exception = False
    assert exc_info.value.error_value == StatusCode.NO_RESPONSE


def test_cmd_write_memory(mcuboot, target):
    data = b"\x00" * 100
    assert mcuboot.write_memory(0, data)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_write_memory_callback(mcuboot, target):
    iteration_counter = 0
    data = b"\x00" * 100

    def callback(transferred: int, total: int) -> None:
        nonlocal iteration_counter
        iteration_counter += 1
        assert transferred == 100
        assert total == 100

    assert mcuboot.write_memory(0, data, progress_callback=callback)
    assert iteration_counter == 1


def test_cmd_fill_memory(mcuboot, target):
    assert mcuboot.fill_memory(0, 10, 0xFFFFFFFF)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_flash_security_disable(mcuboot, target):
    assert mcuboot.flash_security_disable(b"12345678")
    with pytest.raises(McuBootError, match="Backdoor key must by 8 bytes long"):
        mcuboot.flash_security_disable(backdoor_key=b"123456789")


def test_cmd_get_property(mcuboot, target, config):
    for _, tag, _ in PropertyTag:
        values = mcuboot.get_property(tag)
        assert mcuboot.status_code == StatusCode.SUCCESS if values else StatusCode.UNKNOWN_PROPERTY
        assert values == config.get_property_values(tag)


def test_cmd_set_property(mcuboot, target):
    assert not mcuboot.set_property(PropertyTag.VERIFY_WRITES, 0)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_receive_sb_file(mcuboot, target):
    mcuboot._device.fail_step = None
    assert mcuboot.receive_sb_file(bytes(1000))
    assert mcuboot.status_code == StatusCode.SUCCESS

    mcuboot._device.fail_step = StatusCode.ROMLDR_SIGNATURE
    assert not mcuboot.receive_sb_file(bytes(1000))
    assert mcuboot.status_code == StatusCode.ROMLDR_SIGNATURE


def test_cmd_execute(mcuboot, target):
    assert not mcuboot.execute(0, 0, 0)
    assert mcuboot.status_code == StatusCode.FAIL

    assert mcuboot.execute(0x123, 0x0, 0x100)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_call(mcuboot, target):
    assert not mcuboot.call(0, 0)
    assert mcuboot.status_code == StatusCode.FAIL

    assert mcuboot.call(0x600, 0)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_reset_no_reopen(mcuboot, target):
    """Test reset command without reopen"""
    mcuboot._device.fail_step = None
    mcuboot.reopen = False  # set reopen disabled
    assert mcuboot.reset(reopen=False)
    assert mcuboot.status_code == StatusCode.SUCCESS
    mcuboot.open()  # ensure device is again opened for communication


def test_cmd_reset_reopen(mcuboot, target):
    """Test reset command with reopen"""
    mcuboot._device.fail_step = None
    mcuboot.reopen = True  # set reopen enabled
    assert mcuboot.reset()
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_reset_reopen_disabled(mcuboot, target):
    """Test reset command with reopen disabled"""
    mcuboot._device.fail_step = None
    mcuboot.reopen = False
    with pytest.raises(SPSDKError):
        mcuboot.reset(reopen=True)
    mcuboot.open()  # ensure device is again opened for communication
    with pytest.raises(SPSDKError):
        mcuboot.reset()
    mcuboot.open()  # ensure device is again opened for communication


def test_cmd_flash_erase_all_unsecure(mcuboot, target):
    assert not mcuboot.flash_erase_all_unsecure()
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_efuse_read_once(mcuboot, target):
    value = mcuboot.efuse_read_once(0)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND
    assert value is None
    # assert isinstance(value, int)
    # assert value == 0


def test_cmd_efuse_program_once(mcuboot, target):
    assert not mcuboot.efuse_program_once(0, 0x04560123)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_flash_read_once(mcuboot, target):
    value = mcuboot.flash_read_once(0, 8)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND
    assert value is None
    # assert isinstance(value, bytes)


def test_cmd_flash_read_once_invalid(mcuboot):
    with pytest.raises(SPSDKError, match="Invalid count of bytes. Must be 4 or 8"):
        mcuboot.flash_read_once(index=0, count=3)


def test_cmd_flash_program_once(mcuboot, target):
    assert not mcuboot.flash_program_once(0, b"\x00\x00\x00\x00")
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_flash_program_once_invalid_data(mcuboot):
    with pytest.raises(SPSDKError, match="Invalid length of data. Must be aligned to 4 or 8 bytes"):
        mcuboot.flash_program_once(index=0, data=bytes(9))


def test_cmd_flash_read_resource(mcuboot, target):
    value = mcuboot.flash_read_resource(0, 100)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND
    assert value is None
    # assert isinstance(value, bytes)


def test_cmd_reliable_update(mcuboot, target):
    assert not mcuboot.reliable_update(0)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_generate_key_blob(mcuboot, target):
    mcuboot._device.fail_step = None
    assert mcuboot.generate_key_blob(bytes(20))
    mcuboot._device.fail_step = 0
    assert mcuboot.generate_key_blob(bytes(20)) is None
    mcuboot._device.fail_step = 1
    assert mcuboot.generate_key_blob(bytes(20)) is None
    # Currently it's not possible to simulate error in the last step
    # mcuboot._device.fail_step = 2
    # assert mcuboot.generate_key_blob(bytes(20)) is None


# Key provisioning tests
def test_cmd_key_provisioning_enroll(mcuboot):
    mcuboot._device.fail_step = None
    assert mcuboot.kp_enroll()
    mcuboot._device.fail_step = 0
    assert not mcuboot.kp_enroll()


def test_cmd_key_provisioning_set_intrinsic(mcuboot):
    mcuboot._device.fail_step = None
    assert mcuboot.kp_set_intrinsic_key(KeyProvUserKeyType.OTFADKEK, 100)
    mcuboot._device.fail_step = 0
    assert not mcuboot.kp_set_intrinsic_key(KeyProvUserKeyType.OTFADKEK, 100)


def test_cmd_key_provisioning_write_nonvolatile(mcuboot):
    mcuboot._device.fail_step = None
    assert mcuboot.kp_write_nonvolatile(0)
    mcuboot._device.fail_step = 0
    assert not mcuboot.kp_write_nonvolatile(0)


def test_cmd_key_provisioning_read_nonvolatile(mcuboot):
    mcuboot._device.fail_step = None
    assert mcuboot.kp_read_nonvolatile(0)
    mcuboot._device.fail_step = 0
    assert not mcuboot.kp_read_nonvolatile(0)


def test_cmd_key_provisioning_set_user_key(mcuboot, target):
    mcuboot._device.fail_step = None
    data = bytes(100)
    assert mcuboot.kp_set_user_key(KeyProvUserKeyType.SBKEK, data)

    mcuboot._device.fail_step = 0
    data = bytes(100)
    assert not mcuboot.kp_set_user_key(KeyProvUserKeyType.SBKEK, data)


def test_cmd_key_provisioning_write_key_store(mcuboot, target):
    mcuboot._device.fail_step = None
    data = bytes(100)
    assert mcuboot.kp_write_key_store(data)

    mcuboot._device.fail_step = 0
    data = bytes(100)
    assert not mcuboot.kp_write_key_store(data)


def test_cmd_key_provisioning_read_key_store(mcuboot, target):
    mcuboot._device.fail_step = None
    data = mcuboot.kp_read_key_store()
    assert data

    mcuboot._device.fail_step = 0
    data = mcuboot.kp_read_key_store()
    assert data is None


def test_cmd_configure_memory(mcuboot, target):
    response = mcuboot.configure_memory(address=0x100, mem_id=0)
    assert response is True

    response = mcuboot.configure_memory(address=0x100, mem_id=2)
    assert response is False
    response = mcuboot.configure_memory(address=0x100, mem_id=1234)
    assert response is False


def test_load_image(mcuboot, target):
    assert mcuboot.load_image(bytes(1000))
    mcuboot.status_code == StatusCode.SUCCESS


def test_tp_prove_genuinity(mcuboot: McuBoot, target):
    mcuboot._device.fail_step = None
    response = mcuboot.tp_prove_genuinity(0, 0x10)
    assert isinstance(response, int)

    mcuboot._device.fail_step = 0
    response = mcuboot.tp_prove_genuinity(0, 0x10)
    mcuboot._device.fail_step = None
    assert response is None


def test_tp_prove_genuinity_error(mcuboot: McuBoot, target):
    with pytest.raises(McuBootError):
        mcuboot.tp_prove_genuinity(0, 0x1_0000)


def test_tp_set_wrapped_data(mcuboot: McuBoot, target):
    response = mcuboot.tp_set_wrapped_data(0)
    assert response is True

    response = mcuboot.tp_set_wrapped_data(0x100)
    assert response is True


def test_cmd_flash_read_resource_invalid(mcuboot):
    with pytest.raises(McuBootError):
        mcuboot.flash_read_resource(address=1, length=3)
