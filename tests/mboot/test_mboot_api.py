#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot API test suite.

This module contains comprehensive test cases for the MBoot (Master Boot) API functionality,
covering command execution, memory operations, security features, and communication protocols.
The tests validate MBoot command execution, response handling, and error conditions across
various MCU operations including memory management, security workflows, key provisioning,
trust provisioning, and device communication protocols.
"""

from typing import Any

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.mboot.commands import KeyProvUserKeyType
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootCommandError, McuBootConnectionError, McuBootError
from spsdk.mboot.mcuboot import CmdPacket, CommandTag, McuBoot, PropertyTag
from spsdk.mboot.properties import get_properties, get_property_index
from tests.mboot.virtual_device import VirtualDevice


def test_class(mcuboot: McuBoot, target: Any, config: Any) -> None:
    """Test McuBoot class connection state and error handling.

    Verifies that the McuBoot instance properly handles connection state changes
    and raises appropriate exceptions when operations are attempted on a closed
    connection. Tests the behavior of _process_cmd, _read_data, and _send_data
    methods when the connection is closed.

    :param mcuboot: McuBoot instance to test
    :param target: Target configuration for the test
    :param config: Test configuration parameters
    :raises McuBootConnectionError: When operations are performed on closed connection
    """
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


def test_cmd_get_property_list(mcuboot: McuBoot, target: Any, config: Any) -> None:
    """Test command for getting property list from MCU boot interface.

    Verifies that the get_property_list command executes successfully and returns
    the expected number of properties as defined in the configuration.

    :param mcuboot: MCU boot interface instance for communication
    :param target: Target device or configuration object
    :param config: Configuration object containing expected properties count
    :raises AssertionError: If status code is not SUCCESS or property count mismatch
    """
    plist = mcuboot.get_property_list()
    assert mcuboot.status_code == StatusCode.SUCCESS
    assert len(plist) == config.get_properties_count()


def test_cmd_get_memory_list(mcuboot: McuBoot, target: Any) -> None:
    """Test command for getting memory list from MCU.

    This test verifies that the get_memory_list command works correctly by checking
    that it returns a successful status code and the expected number of memory regions.

    :param mcuboot: McuBoot instance for communication with the target device.
    :param target: Target device configuration or instance.
    """
    mlist = mcuboot.get_memory_list()
    assert mcuboot.status_code == StatusCode.SUCCESS
    assert len(mlist) == 2


def test_cmd_read_memory(mcuboot: McuBoot, target: Any) -> None:
    """Test reading memory from MCU using mboot interface.

    Verifies that the read_memory command successfully reads the specified amount
    of data from memory address 0 and returns the correct data length with
    success status code.

    :param mcuboot: McuBoot instance for communication with target device.
    :param target: Target device or mock object for testing.
    """
    data = mcuboot.read_memory(0, 1000)
    assert mcuboot.status_code == StatusCode.SUCCESS
    assert data is not None
    assert len(data) == 1000


def test_cmd_read_memory_callback(mcuboot: McuBoot, target: Any) -> None:
    """Test callback functionality for read memory command.

    This test verifies that the progress callback is properly invoked during
    memory read operations and receives correct parameters for transferred
    and total bytes.

    :param mcuboot: McuBoot instance for testing memory operations.
    :param target: Target device or mock object for the test.
    """
    iteration_counter = 0

    def callback(transferred: int, total: int) -> None:
        """Progress callback function for memory operations testing.

        This callback is used to track the progress of memory read operations
        during testing, validating that the transferred and total byte counts
        meet expected thresholds.

        :param transferred: Number of bytes already transferred (must be >= 500)
        :param total: Total number of bytes to transfer (expected to be 500)
        :raises AssertionError: If transferred bytes < 500 or total bytes != 500
        """
        nonlocal iteration_counter
        iteration_counter += 1
        # NOTE: in our simulation read_memory always returns 1024B :(
        assert transferred >= 500
        assert total == 500

    mcuboot.read_memory(0, 500, progress_callback=callback)
    # TODO: currently we can test only single iteration
    assert iteration_counter == 1


def test_cmd_read_memory_data_abort(mcuboot: McuBoot, target: Any) -> None:
    """Test command read memory with data abort scenario.

    This test verifies that the McuBoot read_memory command properly handles
    a data abort condition by setting up a virtual device to fail with a
    specific status code and confirming the expected error response.

    :param mcuboot: McuBoot instance for testing memory read operations.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = StatusCode.FLASH_OUT_OF_DATE_CFPA_PAGE.tag
    mcuboot.read_memory(0, 1000)
    assert mcuboot.status_code == StatusCode.FLASH_OUT_OF_DATE_CFPA_PAGE


def test_cmd_read_memory_timeout(mcuboot: McuBoot, target: Any) -> None:
    """Test command read memory timeout functionality.

    This test verifies that the McuBoot read_memory command properly handles timeout
    scenarios by testing both status code reporting and exception raising behavior
    when the underlying device fails to respond.

    :param mcuboot: McuBoot instance configured for testing.
    :param target: Test target configuration (unused in this test).
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = 0
    mcuboot.read_memory(0, 100)
    assert mcuboot.status_code == StatusCode.NO_RESPONSE

    mcuboot._cmd_exception = True
    with pytest.raises(McuBootCommandError) as exc_info:
        mcuboot.read_memory(0, 100)
    mcuboot._cmd_exception = False
    assert exc_info.value.error_value == StatusCode.NO_RESPONSE


def test_cmd_write_memory(mcuboot: McuBoot, target: Any) -> None:
    """Test write memory command functionality.

    Verifies that the McuBoot write_memory command successfully writes data to memory
    and returns the correct status code upon completion.

    :param mcuboot: McuBoot instance for testing memory write operations.
    :param target: Target device or mock object for the test.
    """
    data = b"\x00" * 100
    assert mcuboot.write_memory(0, data)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_write_memory_callback(mcuboot: McuBoot, target: Any) -> None:
    """Test write memory command with progress callback functionality.

    Verifies that the write_memory command correctly invokes the progress callback
    during memory write operations and that the callback receives accurate
    progress information.

    :param mcuboot: McuBoot instance for testing memory write operations.
    :param target: Target device or mock object for the test.
    """
    iteration_counter = 0
    data = b"\x00" * 100

    def callback(transferred: int, total: int) -> None:
        """Progress callback function for testing transfer operations.

        This callback function is used in test scenarios to verify that transfer
        progress is reported correctly. It increments an iteration counter and
        validates that both transferred and total bytes equal the expected value.

        :param transferred: Number of bytes transferred so far
        :param total: Total number of bytes to be transferred
        """
        nonlocal iteration_counter
        iteration_counter += 1
        assert transferred == 100
        assert total == 100

    assert mcuboot.write_memory(0, data, progress_callback=callback)
    assert iteration_counter == 1


def test_cmd_fill_memory(mcuboot: McuBoot, target: Any) -> None:
    """Test the fill memory command functionality.

    Verifies that the McuBoot fill_memory command executes successfully
    and returns the expected success status code.

    :param mcuboot: McuBoot instance for testing memory fill operations.
    :param target: Target device or mock object for the test.
    """
    assert mcuboot.fill_memory(0, 10, 0xFFFFFFFF)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_flash_security_disable(mcuboot: McuBoot, target: Any) -> None:
    """Test flash security disable command functionality.

    Verifies that the flash security disable command works correctly with valid
    8-byte backdoor key and raises appropriate error for invalid key length.

    :param mcuboot: McuBoot instance for testing flash security operations.
    :param target: Test target configuration (unused in this test).
    :raises McuBootError: When backdoor key length is not exactly 8 bytes.
    """
    assert mcuboot.flash_security_disable(b"12345678")
    with pytest.raises(McuBootError, match="Backdoor key must by 8 bytes long"):
        mcuboot.flash_security_disable(backdoor_key=b"123456789")


def test_cmd_get_property(mcuboot: McuBoot, target: Any, config: Any) -> None:
    """Test command for getting MCU properties.

    This test verifies that the get_property command works correctly for all
    available property tags by comparing the returned values with expected
    configuration values and checking appropriate status codes.

    :param mcuboot: McuBoot instance for communication with the target device.
    :param target: Target device configuration object.
    :param config: Configuration object containing expected property values.
    """
    for property_tag in get_properties():
        values = mcuboot.get_property(property_tag)
        assert mcuboot.status_code == StatusCode.SUCCESS if values else StatusCode.UNKNOWN_PROPERTY
        assert values == config.get_property_values(get_property_index(property_tag))


def test_cmd_set_property(mcuboot: McuBoot, target: Any) -> None:
    """Test the set_property command functionality.

    This test verifies that the set_property command returns False when attempting
    to set the VERIFY_WRITES property, and confirms that the status code is set
    to UNKNOWN_COMMAND as expected.

    :param mcuboot: McuBoot instance for testing property setting functionality.
    :param target: Target device or mock object for the test operation.
    """
    assert not mcuboot.set_property(PropertyTag.VERIFY_WRITES, 0)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_receive_sb_file(mcuboot: McuBoot, target: Any) -> None:
    """Test receive SB file command functionality.

    Tests the McuBoot receive_sb_file method with both successful and failed scenarios.
    Verifies that the method correctly handles SB file data and returns appropriate
    status codes based on the virtual device configuration.

    :param mcuboot: McuBoot instance configured with VirtualDevice interface.
    :param target: Test target configuration (unused in this test).
    :raises AssertionError: If any of the test assertions fail.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    assert mcuboot.receive_sb_file(bytes(1000))
    assert mcuboot.status_code == StatusCode.SUCCESS

    mcuboot._interface.device.fail_step = StatusCode.ROMLDR_SIGNATURE.tag
    assert not mcuboot.receive_sb_file(bytes(1000))
    assert mcuboot.status_code == StatusCode.ROMLDR_SIGNATURE


def test_cmd_execute(mcuboot: McuBoot, target: Any) -> None:
    """Test the execute command functionality of McuBoot.

    Verifies that the execute command properly handles both failure and success cases,
    and that the status code is correctly updated after each operation.

    :param mcuboot: McuBoot instance to test the execute command on.
    :param target: Target configuration or mock object for testing.
    """
    assert not mcuboot.execute(0, 0, 0)
    assert mcuboot.status_code == StatusCode.FAIL

    assert mcuboot.execute(0x123, 0x0, 0x100)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_call(mcuboot: McuBoot, target: Any) -> None:
    """Test command call functionality with different parameters.

    Verifies that the McuBoot call method properly handles both failing and
    successful command scenarios, and that the status code is correctly updated
    after each call.

    :param mcuboot: McuBoot instance to test command calls on.
    :param target: Target object for the test (not used in current implementation).
    """
    assert not mcuboot.call(0, 0)
    assert mcuboot.status_code == StatusCode.FAIL

    assert mcuboot.call(0x600, 0)
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_reset_no_reopen(mcuboot: McuBoot, target: Any) -> None:
    """Test reset command without reopen functionality.

    Verifies that the McuBoot reset command works correctly when reopen
    is disabled, ensuring the device maintains proper status and can be
    manually reopened for subsequent communication.

    :param mcuboot: McuBoot instance to test reset functionality on.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    mcuboot.reopen = False  # set reopen disabled
    assert mcuboot.reset(reopen=False)
    assert mcuboot.status_code == StatusCode.SUCCESS
    mcuboot.open()  # ensure device is again opened for communication


def test_cmd_reset_reopen(mcuboot: McuBoot, target: Any) -> None:
    """Test reset command with reopen functionality.

    Verifies that the McuBoot reset command works correctly when reopen
    is enabled. The test ensures the virtual device is properly configured,
    enables reopen functionality, executes the reset command, and validates
    the successful status code.

    :param mcuboot: McuBoot instance to test the reset command on.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    mcuboot.reopen = True  # set reopen enabled
    assert mcuboot.reset()
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_cmd_flash_erase_all_unsecure(mcuboot: McuBoot, target: Any) -> None:
    """Test flash erase all unsecure command with unknown command response.

    This test verifies that the flash_erase_all_unsecure command returns False
    and sets the status code to UNKNOWN_COMMAND when the command is not supported.

    :param mcuboot: McuBoot instance for testing flash erase operations.
    :param target: Target device or mock object for the test.
    """
    assert not mcuboot.flash_erase_all_unsecure()
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_efuse_read_once(mcuboot: McuBoot, target: Any) -> None:
    """Test efuse read once command functionality.

    Verifies that the efuse_read_once command returns appropriate status code
    and value when executed. Tests the expected behavior when the command
    is not supported by the target.

    :param mcuboot: McuBoot instance for communication with the target device.
    :param target: Target device configuration or instance.
    """
    value = mcuboot.efuse_read_once(0)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND
    assert value is None
    # assert isinstance(value, int)
    # assert value == 0


def test_cmd_efuse_program_once(mcuboot: McuBoot, target: Any) -> None:
    """Test efuse program once command functionality.

    Verifies that the efuse_program_once command returns False (indicating failure)
    and sets the appropriate status code to UNKNOWN_COMMAND when called with
    test parameters.

    :param mcuboot: McuBoot instance to test the efuse program once command on.
    :param target: Target device or configuration for the test.
    """
    assert not mcuboot.efuse_program_once(0, 0x04560123)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_flash_read_once(mcuboot: McuBoot, target: Any) -> None:
    """Test flash read once command functionality.

    Verifies that the flash_read_once command returns None and sets the status code
    to UNKNOWN_COMMAND when attempting to read from flash memory address 0 with 8 bytes.

    :param mcuboot: McuBoot instance for testing flash read once operations.
    :param target: Target device or configuration for the test.
    """
    value = mcuboot.flash_read_once(0, 8)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND
    assert value is None
    # assert isinstance(value, bytes)


def test_cmd_flash_read_once_invalid(mcuboot: McuBoot) -> None:
    """Test flash read once command with invalid byte count.

    Verifies that the flash_read_once method properly validates the count parameter
    and raises an appropriate error when an invalid byte count is provided.

    :param mcuboot: McuBoot instance to test the flash read once command on.
    :raises SPSDKError: When invalid count of bytes is provided (must be 4 or 8).
    """
    with pytest.raises(SPSDKError, match="Invalid count of bytes. Must be 4 or 8"):
        mcuboot.flash_read_once(index=0, count=3)


def test_cmd_flash_program_once(mcuboot: McuBoot, target: Any) -> None:
    """Test flash program once command functionality.

    Verifies that the flash_program_once command returns False when executed
    and sets the appropriate status code to UNKNOWN_COMMAND.

    :param mcuboot: McuBoot instance for testing the flash program once command.
    :param target: Target device or mock object for the test execution.
    """
    assert not mcuboot.flash_program_once(0, b"\x00\x00\x00\x00")
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_flash_program_once_invalid_data(mcuboot: McuBoot) -> None:
    """Test flash program once command with invalid data length.

    Verifies that the flash_program_once method raises SPSDKError when provided
    with data that is not aligned to 4 or 8 bytes, ensuring proper validation
    of input data length requirements.

    :param mcuboot: McuBoot instance for testing flash programming operations.
    :raises SPSDKError: When data length is not properly aligned.
    """
    with pytest.raises(SPSDKError, match="Invalid length of data. Must be aligned to 4 or 8 bytes"):
        mcuboot.flash_program_once(index=0, data=bytes(9))


def test_cmd_flash_read_resource(mcuboot: McuBoot, target: Any) -> None:
    """Test flash read resource command functionality.

    Verifies that the flash read resource command returns the expected status code
    and response when executed through the McuBoot interface.

    :param mcuboot: McuBoot instance for executing the flash read resource command
    :param target: Target device or configuration for the test
    :raises AssertionError: If the status code is not UNKNOWN_COMMAND or value is not None
    """
    value = mcuboot.flash_read_resource(0, 100)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND
    assert value is None
    # assert isinstance(value, bytes)


def test_cmd_reliable_update(mcuboot: McuBoot, target: Any) -> None:
    """Test reliable update command with unsupported operation.

    This test verifies that the reliable update command returns False when called
    with parameter 0, and that the status code is set to UNKNOWN_COMMAND indicating
    the operation is not supported.

    :param mcuboot: McuBoot instance to test the reliable update command on.
    :param target: Target device or configuration for the test.
    """
    assert not mcuboot.reliable_update(0)
    assert mcuboot.status_code == StatusCode.UNKNOWN_COMMAND


def test_cmd_generate_key_blob(mcuboot: McuBoot, target: Any) -> None:
    """Test key blob generation command with different failure scenarios.

    This test verifies the McuBoot generate_key_blob command behavior under normal
    conditions and when failures occur at different steps of the operation.

    :param mcuboot: McuBoot instance for testing key blob generation.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    assert mcuboot.generate_key_blob(bytes(20))
    mcuboot._interface.device.fail_step = 0
    assert mcuboot.generate_key_blob(bytes(20)) is None
    mcuboot._interface.device.fail_step = 1
    assert mcuboot.generate_key_blob(bytes(20)) is None
    # Currently it's not possible to simulate error in the last step
    # mcuboot._interface.device.fail_step = 2
    # assert mcuboot.generate_key_blob(bytes(20)) is None


# Key provisioning tests
def test_cmd_key_provisioning_enroll(mcuboot: McuBoot) -> None:
    """Test key provisioning enrollment command functionality.

    This test verifies the behavior of the key provisioning enrollment command
    in both success and failure scenarios using a virtual device interface.

    :param mcuboot: McuBoot instance configured with a virtual device interface for testing.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    assert mcuboot.kp_enroll()
    mcuboot._interface.device.fail_step = 0
    assert not mcuboot.kp_enroll()


def test_cmd_key_provisioning_set_intrinsic(mcuboot: McuBoot) -> None:
    """Test key provisioning set intrinsic key functionality.

    This test verifies the behavior of the key provisioning set intrinsic key command
    in both success and failure scenarios using a virtual device interface.

    :param mcuboot: McuBoot instance with virtual device interface for testing.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    assert mcuboot.kp_set_intrinsic_key(KeyProvUserKeyType.OTFADKEK.tag, 100)
    mcuboot._interface.device.fail_step = 0
    assert not mcuboot.kp_set_intrinsic_key(KeyProvUserKeyType.OTFADKEK.tag, 100)


def test_cmd_key_provisioning_write_nonvolatile(mcuboot: McuBoot) -> None:
    """Test key provisioning write non-volatile command functionality.

    This test verifies the key provisioning write non-volatile command behavior
    in both success and failure scenarios by manipulating the virtual device's
    fail_step attribute.

    :param mcuboot: McuBoot instance with virtual device interface for testing.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    assert mcuboot.kp_write_nonvolatile(0)
    mcuboot._interface.device.fail_step = 0
    assert not mcuboot.kp_write_nonvolatile(0)


def test_cmd_key_provisioning_read_nonvolatile(mcuboot: McuBoot) -> None:
    """Test key provisioning read non-volatile memory functionality.

    This test verifies that the key provisioning read non-volatile command works correctly
    under both normal and failure conditions. It tests the behavior when the virtual device
    is configured to succeed and when it's configured to fail at step 0.

    :param mcuboot: McuBoot instance with virtual device interface for testing.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    assert mcuboot.kp_read_nonvolatile(0)
    mcuboot._interface.device.fail_step = 0
    assert not mcuboot.kp_read_nonvolatile(0)


def test_cmd_key_provisioning_set_user_key(mcuboot: McuBoot, target: Any) -> None:
    """Test key provisioning set user key functionality.

    This test verifies the key provisioning set user key command behavior
    in both success and failure scenarios using a virtual device.

    :param mcuboot: McuBoot instance for testing key provisioning operations.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    data = bytes(100)
    assert mcuboot.kp_set_user_key(KeyProvUserKeyType.SBKEK.tag, data)

    mcuboot._interface.device.fail_step = 0
    data = bytes(100)
    assert not mcuboot.kp_set_user_key(KeyProvUserKeyType.SBKEK.tag, data)


def test_cmd_key_provisioning_write_key_store(mcuboot: McuBoot, target: Any) -> None:
    """Test key provisioning write key store functionality.

    This test verifies the key provisioning write key store command behavior
    in both success and failure scenarios using a virtual device interface.

    :param mcuboot: McuBoot instance for testing key provisioning operations.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    data = bytes(100)
    assert mcuboot.kp_write_key_store(data)

    mcuboot._interface.device.fail_step = 0
    data = bytes(100)
    assert not mcuboot.kp_write_key_store(data)


def test_cmd_key_provisioning_read_key_store(mcuboot: McuBoot, target: Any) -> None:
    """Test key provisioning read key store functionality.

    This test verifies the key provisioning read key store command behavior
    in both success and failure scenarios. It tests the mcuboot interface
    with a virtual device, checking that data is returned on success and
    None is returned when the device fails at step 0.

    :param mcuboot: McuBoot instance for testing key provisioning operations.
    :param target: Target device or configuration for the test.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    data = mcuboot.kp_read_key_store()
    assert data

    mcuboot._interface.device.fail_step = 0
    data = mcuboot.kp_read_key_store()
    assert data is None


def test_cmd_configure_memory(mcuboot: McuBoot, target: Any) -> None:
    """Test configure memory command functionality.

    This test verifies that the configure_memory command works correctly with valid
    memory IDs and returns appropriate responses for invalid memory IDs.

    :param mcuboot: McuBoot instance for testing memory configuration commands.
    :param target: Target device or mock object for the test.
    """
    response = mcuboot.configure_memory(address=0x100, mem_id=0)
    assert response is True

    response = mcuboot.configure_memory(address=0x100, mem_id=2)
    assert response is False
    response = mcuboot.configure_memory(address=0x100, mem_id=1234)
    assert response is False


def test_load_image(mcuboot: McuBoot, target: Any) -> None:
    """Test loading image functionality of McuBoot interface.

    This test verifies that the McuBoot load_image method successfully loads
    a byte array image and returns the expected success status code.

    :param mcuboot: McuBoot instance to test image loading functionality.
    :param target: Target configuration or device specification.
    """
    assert mcuboot.load_image(bytes(1000))
    assert mcuboot.status_code == StatusCode.SUCCESS


def test_tp_prove_genuinity(mcuboot: McuBoot, target: Any) -> None:
    """Test Trust Provisioning prove genuinity functionality.

    Tests the McuBoot trust provisioning prove genuinity command with both
    successful and failed scenarios using a virtual device interface.

    :param mcuboot: McuBoot instance with virtual device interface for testing.
    :param target: Target configuration (unused in this test).
    :raises AssertionError: If the virtual device interface is not
        properly configured or responses don't match expected values.
    """
    assert isinstance(mcuboot._interface.device, VirtualDevice)
    mcuboot._interface.device.fail_step = None
    response = mcuboot.tp_prove_genuinity(0, 0x10)
    assert isinstance(response, int)

    mcuboot._interface.device.fail_step = 0
    response = mcuboot.tp_prove_genuinity(0, 0x10)
    mcuboot._interface.device.fail_step = None
    assert response is None


def test_tp_prove_genuinity_error(mcuboot: McuBoot, target: Any) -> None:
    """Test that tp_prove_genuinity raises McuBootError with invalid parameters.

    This test verifies that the tp_prove_genuinity method properly raises a McuBootError
    when called with parameters that should trigger an error condition.

    :param mcuboot: McuBoot instance to test against.
    :param target: Test target configuration.
    :raises McuBootError: Expected exception when tp_prove_genuinity fails.
    """
    with pytest.raises(McuBootError):
        mcuboot.tp_prove_genuinity(0, 0x1_0000)


def test_tp_set_wrapped_data(mcuboot: McuBoot, target: Any) -> None:
    """Test the tp_set_wrapped_data method of McuBoot interface.

    This test verifies that the tp_set_wrapped_data method correctly handles
    different address values and returns the expected boolean response.

    :param mcuboot: McuBoot instance to test the tp_set_wrapped_data method on.
    :param target: Target device or configuration for the test.
    """
    response = mcuboot.tp_set_wrapped_data(0)
    assert response is True

    response = mcuboot.tp_set_wrapped_data(0x100)
    assert response is True


def test_cmd_flash_read_resource_invalid(mcuboot: McuBoot) -> None:
    """Test flash read resource command with invalid parameters.

    This test verifies that the flash_read_resource method properly raises
    McuBootError when called with invalid parameters (address=1, length=3).

    :param mcuboot: McuBoot instance to test the flash read resource functionality.
    :raises McuBootError: Expected exception when invalid parameters are provided.
    """
    with pytest.raises(McuBootError):
        mcuboot.flash_read_resource(address=1, length=3)


def test_available_commands(mcuboot: McuBoot) -> None:
    """Test that available_commands property returns the correct command list.

    This test verifies that the available_commands property correctly returns
    the list of commands that were previously set in available_commands_lst.

    :param mcuboot: McuBoot instance to test the available_commands property on.
    """
    mcuboot.available_commands_lst = [CommandTag.READ_MEMORY, CommandTag.WRITE_MEMORY]
    cmds = mcuboot.available_commands
    assert cmds == [CommandTag.READ_MEMORY, CommandTag.WRITE_MEMORY]
