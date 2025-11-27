#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot virtual device implementation for testing purposes.

This module provides a virtual device that simulates MBoot protocol communication,
enabling comprehensive testing of MBoot commands and responses without requiring
physical hardware. It supports memory operations, security features, and provisioning
commands used in NXP MCU bootloader testing.
"""

import logging
from struct import pack
from typing import Any, Optional, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError
from spsdk.mboot.commands import (
    CmdPacket,
    CommandTag,
    KeyProvOperation,
    ResponseTag,
    TrustProvOperation,
    parse_cmd_response,
)
from spsdk.mboot.error_codes import StatusCode
from spsdk.mboot.exceptions import McuBootDataAbortError
from spsdk.mboot.memories import ExtMemId
from spsdk.utils.interfaces.commands import CmdResponseBase
from spsdk.utils.interfaces.device.base import DeviceBase
from tests.mboot.device_config import DevConfig


########################################################################################################################
# Helper functions
########################################################################################################################
def pack_response(tag: ResponseTag, *params: int) -> tuple[bool, bytes]:
    """Pack response data into binary format for mboot protocol.

    Creates a binary response packet with the specified tag and parameters
    following the mboot protocol structure.

    :param tag: Response tag indicating the type of response
    :param params: Variable number of integer parameters to include in response
    :return: Tuple containing success status (always True) and packed binary data
    """
    return True, pack(f"<4B{len(params)}I", tag.tag, 0, 0, len(params), *params)


def set_error_code(step_index: int, fail_step: Optional[int]) -> int:
    """Set error code based on step index and failure condition.

    This method determines whether to return a success or failure status code
    by comparing the current step index with an optional failure step parameter.

    :param step_index: Current step index in the process.
    :param fail_step: Optional step index where failure should occur, None means no failure.
    :return: Status code tag indicating success or failure.
    """
    if fail_step is not None and fail_step == step_index:
        return StatusCode.FAIL.tag
    return StatusCode.SUCCESS.tag


########################################################################################################################
# Commands functions
########################################################################################################################
def cmd_call(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Simulate call command execution for virtual device.

    Executes a call command with the provided address and parameters. Returns success
    status if address is non-zero, otherwise returns failure status.

    :param args: Variable arguments where first argument is the call address and second is unused parameter.
    :param kwargs: Additional keyword arguments (unused).
    :raises AssertionError: If number of arguments is not exactly 2.
    :return: Tuple containing success flag and packed response bytes with call command result.
    """
    assert len(args) == 2
    address, _ = args
    status = StatusCode.FAIL.tag if address == 0 else StatusCode.SUCCESS.tag
    return pack_response(ResponseTag.GENERIC, status, CommandTag.CALL.tag)


def cmd_configure_memory(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Configure memory command handler for virtual device.

    Handles the configure memory command by validating the memory ID and address parameters.
    Returns success status if memory ID is valid (in ExtMemId tags or 0), otherwise returns failure.

    :param args: Command arguments containing memory_id and address
    :param kwargs: Additional keyword arguments (unused)
    :raises AssertionError: If incorrect number of arguments provided or address is negative
    :return: Tuple containing success flag and packed response bytes with status
    """
    assert len(args) == 2
    memory_id, address = args
    assert address >= 0
    status = (
        StatusCode.FAIL.tag if memory_id not in ExtMemId.tags() + [0] else StatusCode.SUCCESS.tag
    )
    return pack_response(ResponseTag.GENERIC, status, CommandTag.CONFIGURE_MEMORY.tag)


def cmd_flash_erase_all(*args: Any, **_kwargs: Any) -> tuple[bool, bytes]:
    """Simulate flash erase all command for virtual device.

    This method simulates the flash erase all command response for testing purposes.
    It validates the input arguments and returns a successful response packet.

    :param args: Command arguments, expects exactly one argument (memory ID).
    :param _kwargs: Additional keyword arguments (unused).
    :raises AssertionError: If the number of arguments is not exactly 1.
    :return: Tuple containing success status and response bytes with generic response tag.
    """
    assert len(args) == 1
    # TODO remove unused code: mem_id = args[0]
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(
        ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.FLASH_ERASE_ALL.tag
    )


def cmd_flash_erase_region(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Simulate flash erase region command for virtual device.

    Validates the erase operation parameters and returns appropriate status response.
    Checks if the address is within flash memory bounds and if the length doesn't
    exceed available flash size.

    :param args: Command arguments containing address, length, and memory ID
    :param kwargs: Keyword arguments containing device configuration
    :return: Tuple of success flag and response bytes with operation status
    """
    assert len(args) == 3
    cfg = kwargs["config"]
    address, length, _ = args  # mem_id is not used in this implementation
    # TODO: check arguments
    if address < cfg.flash_start_address or address >= cfg.flash_start_address + cfg.flash_size:
        status = StatusCode.FLASH_ADDRESS_ERROR
    elif length > (cfg.flash_size - address):
        status = StatusCode.FLASH_SIZE_ERROR
    else:
        status = StatusCode.SUCCESS
    return pack_response(ResponseTag.GENERIC, status.tag, CommandTag.FLASH_ERASE_ALL.tag)


def cmd_execute(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Execute command simulation for virtual device.

    Simulates the execution of code at a specified address. The command succeeds
    if the argument value is less than the address value, otherwise it fails.

    :param args: Variable arguments containing address, argument, and unused parameter
    :param kwargs: Additional keyword arguments (unused)
    :return: Tuple containing success status and packed response bytes
    """
    assert len(args) == 3
    address, arg, _ = args
    status = StatusCode.SUCCESS.tag if arg < address else StatusCode.FAIL.tag
    return pack_response(ResponseTag.GENERIC, status, CommandTag.EXECUTE.tag)


def cmd_read_memory(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Simulate read memory command for virtual MCU boot device.

    Handles the read memory command simulation including success and failure scenarios.
    The method supports multi-packet responses for large memory reads and can simulate
    various error conditions based on the fail_step parameter.

    :param args: Command arguments containing address, length, and memory ID.
    :param kwargs: Additional parameters including config, response index, fail step, and caller reference.
    :return: Tuple of (is_final_response, response_data) where is_final_response indicates if this is the last packet.
    :raises McuBootDataAbortError: When fail_step is set and simulating data abort error.
    :raises TimeoutError: When fail_step is set and simulating timeout error.
    """
    assert len(args) == 3
    _, length, _ = args  # address, mem_id not used in this implementation
    cfg = kwargs["config"]
    response_index = kwargs["index"]
    fail_step = kwargs["fail_step"]
    caller = kwargs["full_ref"]

    if fail_step is not None:
        if response_index == 0:
            return pack_response(ResponseTag.READ_MEMORY, StatusCode.SUCCESS.tag, length)
        if response_index == 1:
            caller._response_index += 1
            error = McuBootDataAbortError if fail_step else TimeoutError
            raise error()
        return pack_response(ResponseTag.GENERIC, fail_step, CommandTag.READ_MEMORY.tag)

    if response_index == 0:
        # TODO: check arguments
        return pack_response(ResponseTag.READ_MEMORY, StatusCode.SUCCESS.tag, length)
    if response_index == 1:
        return False, b"\x00" * cfg.max_packet_size
    if response_index > 1 and (response_index - 1) * cfg.max_packet_size < length:
        return False, b"\x00" * cfg.max_packet_size
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.READ_MEMORY.tag)


def cmd_write_memory(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Simulate write memory command for virtual device.

    This method simulates the write memory command response for testing purposes.
    Currently performs basic argument validation and returns a success response.

    :param args: Command arguments containing address, length, and memory ID
    :param kwargs: Additional keyword arguments including device configuration
    :return: Tuple containing success status and packed response bytes
    :raises AssertionError: If incorrect number of arguments provided
    """
    assert len(args) == 3
    # TODO remove unused code: address, length, mem_id = args
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.WRITE_MEMORY.tag)


def cmd_fill_memory(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Command to fill memory with a specified pattern.

    This method simulates the fill memory command for a virtual device by validating
    the input arguments and returning a successful response packet.

    :param args: Command arguments containing address, length, and pattern values.
    :param kwargs: Additional keyword arguments including device configuration.
    :raises AssertionError: If the number of arguments is not exactly 3.
    :return: Tuple containing success status and response bytes with fill memory command tag.
    """
    assert len(args) == 3
    # TODO remove unused code: address, length, pattern = args
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.FILL_MEMORY.tag)


def cmd_flash_security_disable(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Disable flash security command handler for virtual device.

    This method simulates the flash security disable command by returning a successful
    response without performing actual security operations. Used for testing and
    virtual device simulation purposes.

    :param args: Command arguments containing security keys (expects exactly 2 arguments).
    :param kwargs: Additional keyword arguments including device configuration.
    :return: Tuple containing success status and packed response bytes with success status.
    """
    assert len(args) == 2
    # TODO remove unused code: key1, key2 = args
    # TODO remove unused code: cfg = kwargs['config']
    # TODO: check arguments
    return pack_response(
        ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.FLASH_SECURITY_DISABLE.tag
    )


def cmd_load_image(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Load image command handler for virtual device.

    Handles the load image command by returning a successful response with generic tag.
    This is a mock implementation for testing purposes that always returns success.

    :param args: Variable length argument list, expects exactly one argument.
    :param kwargs: Arbitrary keyword arguments (unused).
    :raises AssertionError: If the number of arguments is not exactly 1.
    :return: Tuple containing success status and packed response bytes with generic tag and success status.
    """
    assert len(args) == 1
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, 0)


def cmd_get_property(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Get property command handler for virtual device.

    Handles the get property command by retrieving property values from the device
    configuration based on the provided tag and memory ID. Returns a packed response
    with either the property values on success or an error status for unknown properties.

    :param args: Command arguments containing property tag and memory ID
    :param kwargs: Keyword arguments containing device configuration
    :return: Tuple of success flag and packed response bytes
    """
    assert len(args) == 2
    cfg = kwargs["config"]
    tag, _ = args  # mem_id is currently unused
    values = cfg.get_property_values(tag)
    if values:
        return pack_response(ResponseTag.GET_PROPERTY, StatusCode.SUCCESS.tag, *values)
    return pack_response(ResponseTag.GET_PROPERTY, StatusCode.UNKNOWN_PROPERTY.tag, tag)


def cmd_set_property(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Set property command handler for virtual device.

    Handles the set property command by packing a success response with the provided tag.
    This is a mock implementation for testing purposes that always returns success.

    :param args: Variable arguments containing tag and value (expects exactly 2 arguments)
    :param kwargs: Keyword arguments (config parameter currently unused)
    :raises AssertionError: If number of arguments is not exactly 2
    :return: Tuple containing success status and packed response bytes
    """
    assert len(args) == 2
    # TODO remove unused code: cfg = kwargs['config']
    tag, _ = args  # value is currently unused
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, tag)


def cmd_receive_sb_file(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Simulate receiving a Secure Binary file command response.

    This method simulates the MCU bootloader's response to a RECEIVE_SB_FILE command,
    with optional failure injection for testing purposes.

    :param args: Command arguments, expects exactly one argument.
    :param kwargs: Keyword arguments containing response configuration.
        - index: Response index for failure simulation.
        - fail_step: Status code to return for simulated failure, or falsy for success.
        - full_ref: Reference to the calling object for state manipulation.
    :raises McuBootDataAbortError: When simulating a data abort condition.
    :return: Tuple containing success flag and packed response bytes.
    """
    assert len(args) == 1
    response_index = kwargs["index"]
    fail_step = kwargs["fail_step"]
    caller = kwargs["full_ref"]
    if not fail_step:
        return pack_response(
            ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.RECEIVE_SB_FILE.tag
        )
    # introducing failures
    if response_index == 0:
        return pack_response(
            ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.RECEIVE_SB_FILE.tag
        )
    if response_index == 1:
        caller._response_index += 1
        raise McuBootDataAbortError()
    return pack_response(ResponseTag.GENERIC, fail_step, CommandTag.RECEIVE_SB_FILE.tag)


def cmd_reset(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Simulate reset command for virtual device.

    This method simulates the reset command behavior in a virtual device environment.
    It can be configured to either succeed or fail based on the fail_step parameter.

    :param args: Variable length argument list (must be empty).
    :param kwargs: Keyword arguments containing configuration options.
        - fail_step: Flag indicating whether the reset command should fail.
    :return: Tuple containing success status and response bytes with reset command result.
    """
    assert len(args) == 0
    fail_step = kwargs["fail_step"]
    if fail_step:
        return pack_response(ResponseTag.GENERIC, StatusCode.FAIL.tag, CommandTag.RESET.tag)
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.RESET.tag)


def cmd_generate_keyblob(
    *args: Any, index: int, fail_step: Optional[int], **kwargs: Any
) -> tuple[bool, bytes]:
    """Generate key blob command response for virtual device testing.

    Simulates the key blob generation command response based on the provided index
    and optional failure step. Returns different response formats depending on
    the index value and command arguments.

    :param args: Variable arguments passed to the command, where args[2] is used for conditional logic.
    :param index: Response variant index (0, 1, or 2) determining the response format.
    :param fail_step: Optional step number where the command should fail for testing purposes.
    :param kwargs: Additional keyword arguments (unused).
    :return: Tuple containing success status and response bytes.
    """
    response = {
        0: pack_response(ResponseTag.KEY_BLOB_RESPONSE, set_error_code(index, fail_step), 20),
        1: (
            pack_response(
                ResponseTag.GENERIC,
                set_error_code(index, fail_step),
                CommandTag.GENERATE_KEY_BLOB.tag,
            )
            if args[2] == 0
            else (False, bytes(20))
        ),
        2: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.GENERATE_KEY_BLOB.tag
        ),
    }[index]
    return response


######################################
# Key Provisioning support functions #
######################################
def cmd_key_prov_no_data(index: int, fail_step: Optional[int]) -> tuple[bool, bytes]:
    """Generate key provisioning response command with no data.

    Creates a response for key provisioning operations that contains only the response
    tag and error code without additional data payload.

    :param index: Index value used for error code generation
    :param fail_step: Optional step number where failure should occur, None for success
    :return: Tuple containing success status and packed response bytes
    """
    return pack_response(
        ResponseTag.KEY_PROVISIONING_RESPONSE, set_error_code(index, fail_step), 20
    )


def cmd_key_prov_write(index: int, fail_step: Optional[int]) -> tuple[bool, bytes]:
    """Simulate key provisioning write command response.

    Generates appropriate response data for key provisioning write operations
    based on the provided index and optional failure step.

    :param index: Response index to determine which type of response to generate.
    :param fail_step: Optional step number where the operation should fail, defaults to None.
    :return: Tuple containing success status and response bytes data.
    """
    return {
        0: cmd_key_prov_no_data(index, fail_step),
        1: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.KEY_PROVISIONING.tag
        ),
    }[index]


def cmd_key_prov_read(index: int, fail_step: Optional[int]) -> tuple[bool, bytes]:
    """Read key provisioning data based on index.

    Simulates key provisioning read command for virtual device testing.
    Returns different responses based on the provided index value.

    :param index: Index determining the type of response (0: no data, 1: 20 bytes, 2: packed response).
    :param fail_step: Optional step number where the operation should fail for testing purposes.
    :return: Tuple containing success status (bool) and response data (bytes).
    """
    return {
        0: cmd_key_prov_no_data(index, fail_step),
        1: (False, bytes(20)),
        2: pack_response(
            ResponseTag.GENERIC, set_error_code(index, fail_step), CommandTag.KEY_PROVISIONING.tag
        ),
    }[index]


def cmd_key_provisioning(
    *args: Any, index: int, fail_step: Optional[int], **kwargs: Any
) -> tuple[bool, bytes]:
    """Handle key provisioning command operations.

    Executes various key provisioning operations based on the provided operation type.
    Maps operation tags to appropriate response functions and processes the request.

    :param args: Variable arguments where first argument is the key provisioning operation.
    :param index: Index parameter for the key provisioning operation.
    :param fail_step: Optional step number where the operation should fail for testing purposes.
    :param kwargs: Additional keyword arguments.
    :return: Tuple containing success status and response data bytes.
    """
    response_function = {
        KeyProvOperation.ENROLL.tag: cmd_key_prov_no_data,
        KeyProvOperation.SET_INTRINSIC_KEY.tag: cmd_key_prov_no_data,
        KeyProvOperation.WRITE_NON_VOLATILE.tag: cmd_key_prov_no_data,
        KeyProvOperation.READ_NON_VOLATILE.tag: cmd_key_prov_no_data,
        KeyProvOperation.SET_USER_KEY.tag: cmd_key_prov_write,
        KeyProvOperation.WRITE_KEY_STORE.tag: cmd_key_prov_write,
        KeyProvOperation.READ_KEY_STORE.tag: cmd_key_prov_read,
    }[args[0]]
    response = response_function(index, fail_step)
    return response


def cmd_no_command(*args: Any, **kwargs: Any) -> tuple[bool, bytes]:
    """Handle no-command request for virtual device.

    This method processes a no-command request and returns a successful response
    with the appropriate command tag. It's used in virtual device simulation
    to handle empty or placeholder commands.

    :param args: Variable length argument list (unused).
    :param kwargs: Arbitrary keyword arguments (unused).
    :return: Tuple containing success status and packed response bytes.
    """
    return pack_response(ResponseTag.GENERIC, StatusCode.SUCCESS.tag, CommandTag.NO_COMMAND.tag)


########################################
# Trust Provisioning support functions #
########################################
def cmd_trust_prov_prove_genuinity(index: int, fail_step: Optional[int]) -> tuple[bool, bytes]:
    """Simulate trust provisioning prove genuinity command for virtual device.

    This method simulates the trust provisioning prove genuinity command response,
    including error handling based on the fail_step parameter. Returns a packed
    response with either success status and response length or failure status.

    :param index: Command index for error code determination.
    :param fail_step: Optional step number where the command should fail, None for success.
    :return: Tuple containing success status and packed response bytes.
    """
    error_code = set_error_code(index, fail_step)
    if error_code == StatusCode.FAIL:
        return pack_response(ResponseTag.TRUST_PROVISIONING_RESPONSE, error_code, 0)

    tp_response_length = 0x2000
    return pack_response(
        ResponseTag.TRUST_PROVISIONING_RESPONSE, StatusCode.SUCCESS.tag, tp_response_length
    )


def cmd_trust_prov_set_wrap_data(index: int, fail_step: Optional[int]) -> tuple[bool, bytes]:
    """Set trust provisioning wrap data command response.

    Packs a response for the trust provisioning set wrap data command with optional error simulation.

    :param index: Index parameter for the trust provisioning operation.
    :param fail_step: Optional step number where the operation should fail for testing purposes.
    :return: Tuple containing success status and packed response bytes.
    """
    return pack_response(ResponseTag.TRUST_PROVISIONING_RESPONSE, set_error_code(index, fail_step))


def cmd_trust_provisioning(
    *args: Any, index: int, fail_step: Optional[int], **kwargs: Any
) -> tuple[bool, bytes]:
    """Execute trust provisioning command with specified operation.

    Handles trust provisioning operations by dispatching to appropriate response
    functions based on the command ID. Supports operations like proving genuinity
    and setting wrapped data.

    :param args: Variable arguments where first argument contains command ID with operation type
    :param index: Index parameter passed to the response function
    :param fail_step: Optional step number where operation should fail for testing purposes
    :param kwargs: Additional keyword arguments (unused)
    :return: Tuple containing success status and response data bytes
    """
    response_functions = {
        TrustProvOperation.PROVE_GENUINITY: cmd_trust_prov_prove_genuinity,
        TrustProvOperation.ISP_SET_WRAPPED_DATA: cmd_trust_prov_set_wrap_data,
    }
    command_id = args[0] & 0xFF
    response_function = response_functions[TrustProvOperation.from_tag(command_id)]
    response = response_function(index, fail_step)
    return response


########################################################################################################################
# Virtual Device Class
########################################################################################################################
class VirtualDevice(DeviceBase):
    """Virtual device implementation for SPSDK mboot testing.

    This class simulates a physical device for testing mboot communication protocols
    and command processing without requiring actual hardware. It provides a complete
    virtual environment for validating bootloader commands and responses.

    :cvar CMD: Command mapping dictionary linking CommandTag values to their handler functions.
    """

    CMD = {
        CommandTag.NO_COMMAND: cmd_no_command,
        CommandTag.FLASH_ERASE_ALL: cmd_flash_erase_all,
        CommandTag.FLASH_ERASE_REGION: cmd_flash_erase_region,
        CommandTag.READ_MEMORY: cmd_read_memory,
        CommandTag.WRITE_MEMORY: cmd_write_memory,
        CommandTag.FILL_MEMORY: cmd_fill_memory,
        CommandTag.FLASH_SECURITY_DISABLE: cmd_flash_security_disable,
        CommandTag.GET_PROPERTY: cmd_get_property,
        CommandTag.RECEIVE_SB_FILE: cmd_receive_sb_file,
        CommandTag.EXECUTE: cmd_execute,
        CommandTag.CALL: cmd_call,
        CommandTag.RESET: cmd_reset,
        CommandTag.SET_PROPERTY: cmd_set_property,
        CommandTag.FLASH_ERASE_ALL_UNSECURE: None,
        CommandTag.FLASH_PROGRAM_ONCE: None,
        CommandTag.FLASH_READ_ONCE: None,
        CommandTag.FLASH_READ_RESOURCE: None,
        CommandTag.CONFIGURE_MEMORY: cmd_configure_memory,
        CommandTag.RELIABLE_UPDATE: None,
        CommandTag.GENERATE_KEY_BLOB: cmd_generate_keyblob,
        CommandTag.KEY_PROVISIONING: cmd_key_provisioning,
        CommandTag.TRUST_PROVISIONING: cmd_trust_provisioning,
    }

    def __init__(self, config: DevConfig, **kwargs: Any) -> None:
        """Initialize virtual device instance.

        Sets up the virtual device with the provided configuration and initializes
        all internal state variables for command processing and communication.

        :param config: Device configuration containing setup parameters.
        :param kwargs: Additional keyword arguments for device initialization.
        """
        self._opened = False
        self._timeout = 0
        self._dev_conf = config
        self._cmd_tag = 0
        self._cmd_params: list[int] = []
        self._cmd_data = bytes()
        self._response_index = 0
        self._need_data_split = True
        self.fail_step: Optional[int] = None

    @property
    def is_opened(self) -> bool:
        """Check if the virtual device is currently opened.

        :return: True if the device is opened, False otherwise.
        """
        return self._opened

    def open(self) -> None:
        """Open the virtual device for communication.

        Sets the internal state to indicate that the virtual device is ready
        to accept and process commands from the host.

        :raises SPSDKError: If the device is already opened or in an invalid state.
        """
        self._opened = True

    def close(self) -> None:
        """Close the virtual device connection.

        Marks the virtual device as closed by setting the internal opened state to False.
        This method is used to properly terminate the connection to the virtual device
        and should be called when the device is no longer needed.
        """
        self._opened = False

    def __str__(self) -> str:
        """Get string representation of the virtual device.

        :return: String identifier for the virtual device.
        """
        return "Virtual Device"

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the virtual device and generate appropriate response.

        This method processes commands sent to the virtual device by validating the command tag
        and executing the corresponding command handler. If the command is valid, it calls the
        appropriate method from the CMD dictionary to generate a response. For invalid commands,
        it returns a generic error response with UNKNOWN_COMMAND status.

        :param length: Number of bytes to read from the device.
        :param timeout: Optional timeout value in seconds for the read operation.
        :return: Raw response data as bytes, either parsed command response or raw data.
        """
        if self._dev_conf.valid_cmd(self._cmd_tag):
            method = self.CMD[CommandTag.from_tag(self._cmd_tag)]
            assert method
            cmd, raw_data = method(
                *self._cmd_params,
                index=self._response_index,
                config=self._dev_conf,
                fail_step=self.fail_step,
                full_ref=self,
            )
            self._response_index += 1
        else:
            cmd, raw_data = pack_response(
                ResponseTag.GENERIC, StatusCode.UNKNOWN_COMMAND.tag, self._cmd_tag
            )
        logging.debug(  # pylint: disable=logging-not-lazy
            f"RAW-IN [{len(raw_data)}]: " + ", ".join(f"{b:02X}" for b in raw_data)
        )
        return parse_cmd_response(raw_data) if cmd else raw_data  # type: ignore

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write raw data to the virtual device.

        Logs the outgoing data in hexadecimal format for debugging purposes.

        :param data: Raw bytes to be written to the device.
        :param timeout: Optional timeout value in seconds for the write operation.
        """
        logging.debug(  # pylint: disable=logging-not-lazy
            f"RAW-OUT[{len(data)}]: " + ", ".join(f"{b:02X}" for b in data)
        )

    @property
    def timeout(self) -> int:
        """Get the timeout value for the virtual device.

        :return: Timeout value in seconds.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set the timeout value for the virtual device.

        :param value: Timeout value in seconds.
        """
        self._timeout = value


class VirtualMbootInterface:
    """Virtual MBoot interface for testing and simulation purposes.

    This class provides a virtual implementation of the MBoot communication interface,
    allowing for testing and simulation of MBoot operations without requiring actual
    hardware devices. It wraps a VirtualDevice instance and provides the standard
    MBoot interface methods for opening, closing, and communicating with the virtual device.
    """

    def __init__(self, device: VirtualDevice) -> None:
        """Initialize the MBootInterface object.

        :param device: The device instance to be used for MBoot communication.
        """
        self.device: VirtualDevice = device

    def open(self) -> None:
        """Open the interface.

        This method initializes and opens the virtual device interface for communication.

        :raises SPSDKError: If the device interface fails to open.
        """
        self.device.open()

    def close(self) -> None:
        """Close the interface.

        This method properly closes the underlying device connection and cleans up any resources.
        """
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Check if the virtual device interface is currently open.

        :return: True if the interface is open, False otherwise.
        """
        return self.device.is_opened

    @property
    def need_data_split(self) -> bool:
        """Check if the device requires data splitting for communication.

        This method determines whether the underlying device implementation
        needs to split data into smaller chunks during transmission.

        :return: True if data splitting is required, False otherwise.
        """
        return self.device._need_data_split

    @need_data_split.setter
    def need_data_split(self, value: bool) -> None:
        """Set the data split requirement flag for the virtual device.

        This method configures whether the virtual device should split data during operations.

        :param value: Boolean flag indicating if data splitting is required.
        """
        self.device._need_data_split = value

    @classmethod
    def scan(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> list[Self]:
        """Scan for virtual devices with specified parameters.

        This method provides a base implementation for scanning virtual devices
        in the test environment. Subclasses should override this method to implement
        actual device discovery logic.

        :param params: Connection parameters for device scanning.
        :param timeout: Maximum time in seconds to wait for device discovery.
        :param extra_params: Additional optional parameters for device scanning.
        :return: List of discovered virtual device instances.
        """
        return []

    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        """Read data from the virtual device.

        This method delegates the read operation to the underlying device implementation,
        using the specified length or defaulting to 0 if no length is provided.

        :param length: Number of bytes to read from the device. If None, defaults to 0.
        :return: Command response object or raw bytes data from the device.
        """
        return self.device.read(length or 0)

    def write_data(self, data: bytes) -> None:
        """Encapsulate data into frames and send them to device.

        :param data: Data to be sent to the virtual device.
        """
        self.device._cmd_data = data
        self.device.write(data)

    def write_command(self, packet: CmdPacket) -> None:
        """Encapsulate command into frames and send them to device.

        The method processes the command packet, exports its data, and configures
        the virtual device with command parameters before sending the data.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: When packet type is incorrect or data export fails
        """
        data = packet.export(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        self.device._cmd_tag = packet.header.tag
        self.device._cmd_params = packet.params
        self.device._response_index = 0
        self.device.write(data)
