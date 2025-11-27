#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDP (Serial Download Protocol) module tests.

This module contains comprehensive test cases for the SDP functionality,
including HAB (High Assurance Boot) locked device scenarios and error
handling validation.
"""

from struct import pack
from typing import Optional

import pytest
from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError
from spsdk.sdp.commands import CmdResponse, CommandTag, ResponseValue
from spsdk.sdp.error_codes import StatusCode
from spsdk.sdp.exceptions import SdpError
from spsdk.sdp.sdp import SDP, CmdPacket
from spsdk.utils.interfaces.device.base import DeviceBase


class VirtualDevice(DeviceBase):
    """Mock SDP device interface for testing purposes.

    This class provides a virtual implementation of the Serial Download Protocol (SDP)
    device interface that returns predefined responses from a configured sequence.
    It enables testing of SDP communication flows without requiring actual hardware,
    making it ideal for unit tests and development scenarios.
    """

    def __init__(self, respond_sequence: list[CmdResponse]) -> None:
        """Initialize the mock SDP interface with predefined response sequence.

        Sets up a mock SDP (Serial Download Protocol) interface that will return
        responses from the provided sequence when commands are executed.

        :param respond_sequence: List of command responses to be returned in order.
        """
        self.respond_sequence = respond_sequence
        self._timeout = 0

    @property
    def is_opened(self) -> bool:
        """Check if the connection is opened.

        :return: True if the connection is opened, False otherwise.
        """
        return True

    def open(self) -> None:
        """Open the SDP connection.

        Establishes a connection to the target device using the Serial Download Protocol (SDP).
        This method initializes the communication interface and prepares it for data transfer operations.

        :raises SPSDKConnectionError: If the connection cannot be established.
        :raises SPSDKError: If there's an error during the opening process.
        """
        pass

    def close(self) -> None:
        """Close the SDP connection.

        This method properly closes the SDP (Serial Download Protocol) connection
        and releases any associated resources.
        """
        pass

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the mock SDP interface.

        This method simulates reading data by returning the next response from the
        pre-configured response sequence. It's used for testing SDP communication
        without actual hardware.

        :param length: Number of bytes to read (ignored in mock implementation).
        :param timeout: Optional timeout in milliseconds for the read operation.
        :return: Next response bytes from the configured sequence.
        """
        return self.respond_sequence.pop(0)  # type: ignore

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to the SDP interface.

        Sends the provided data bytes through the SDP (Serial Download Protocol) interface
        to the target device.

        :param data: The byte data to be written to the SDP interface.
        :param timeout: Optional timeout value in seconds for the write operation.
        """
        pass

    def __str__(self) -> str:
        """Get string representation of the VirtualDevice.

        :return: String identifier for the virtual device instance.
        """
        return "VirtualDevice"

    @property
    def timeout(self) -> int:
        """Get the timeout value for SDP operations.

        :return: Timeout value in seconds.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set the timeout value for SDP operations.

        :param value: Timeout value in seconds for SDP communication operations.
        """
        self._timeout = value


class VirtualSDPInterface:
    """Virtual SDP interface for testing purposes.

    This class provides a mock implementation of the SDP (Serial Download Protocol)
    interface that wraps a virtual device for unit testing and simulation scenarios.
    It implements the standard SDP interface contract while communicating with
    virtual devices instead of real hardware.
    """

    def __init__(self, device: VirtualDevice) -> None:
        """Initialize the virtual device interface.

        Sets up the connection to a virtual device for testing purposes.

        :param device: Virtual device instance to be used for communication.
        """
        self.device = device

    def open(self) -> None:
        """Open the interface.

        This method establishes a connection to the underlying device interface,
        making it ready for communication operations.

        :raises SPSDKError: If the device interface cannot be opened or is already in use.
        """
        self.device.open()

    def close(self) -> None:
        """Close the interface.

        This method properly closes the underlying device interface and releases
        any associated resources.

        :raises SPSDKError: If the device interface fails to close properly.
        """
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open.

        :return: True if the interface is currently open, False otherwise.
        """
        return self.device.is_opened

    @classmethod
    def scan(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> list[Self]:
        """Scan for available devices using specified parameters.

        This method provides a base implementation for device scanning functionality
        and returns an empty list as it's not actively used in the current implementation.

        :param params: Connection parameters for device scanning
        :param timeout: Timeout value in seconds for the scanning operation
        :param extra_params: Additional optional parameters for scanning configuration
        :return: List of discovered device instances
        """
        return []  # not used

    def read(self, length: Optional[int] = None) -> bytes:
        """Read data from the SDP device.

        This method reads a specified number of bytes from the connected SDP device.
        If no length is specified, it defaults to reading 0 bytes.

        :param length: Number of bytes to read from the device. Defaults to None (0 bytes).
        :return: Raw bytes data read from the device.
        """
        return self.device.read(length or 0)

    def write_data(self, data: bytes) -> None:
        """Write data to the SDP device.

        This method sends the provided data bytes directly to the connected SDP device
        through the underlying communication interface.

        :param data: Raw bytes to be written to the device.
        :raises SPSDKError: If the write operation fails or device is not accessible.
        """
        self.device.write(data)

    def write_command(self, packet: CmdPacket) -> None:
        """Write command packet to the connected device.

        Exports the command packet to binary data and sends it to the device through
        the underlying communication interface.

        :param packet: Command packet to be written to the device.
        :raises SPSDKAttributeError: If the packet cannot be exported (incorrect packet type).
        """
        data = packet.export()
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        self.device.write(data)


def test_sdp_hab_locked() -> None:
    """Test SDP HAB locked status detection.

    Verifies that the SDP interface correctly detects when HAB (High Assurance Boot)
    is locked by testing the _send_data method with a virtual device that responds
    with LOCKED and HAB_SUCCESS status codes. Confirms that the SDP instance properly
    interprets these responses and sets the appropriate status codes.
    """
    sdp = SDP(
        VirtualSDPInterface(
            VirtualDevice(
                respond_sequence=[  # type: ignore
                    CmdResponse(True, pack(">I", ResponseValue.LOCKED.tag)),
                    CmdResponse(True, pack(">I", ResponseValue.HAB_SUCCESS.tag)),
                ]
            )
        )
    )
    assert sdp.is_opened
    assert sdp._send_data(CmdPacket(CommandTag.READ_REGISTER, 0, 0, 0), b"")
    assert sdp.hab_status == StatusCode.HAB_IS_LOCKED
    assert sdp.status_code == StatusCode.SUCCESS


def test_sdp_read_hab_locked() -> None:
    """Test SDP read operation when HAB (High Assurance Boot) is locked.

    This test verifies that the SDP read method behaves correctly when the device
    HAB is in a locked state, ensuring proper status code and HAB status reporting.

    :raises AssertionError: If any of the expected conditions are not met during testing.
    """
    sdp = SDP(
        VirtualSDPInterface(
            VirtualDevice(
                respond_sequence=[  # type: ignore
                    CmdResponse(True, pack(">I", ResponseValue.LOCKED.tag)),
                    CmdResponse(False, b"0000"),
                    CmdResponse(True, pack(">I", ResponseValue.HAB_SUCCESS.tag)),
                ]
            )
        )
    )
    assert sdp.is_opened
    assert sdp.read(0x20000000, 4)
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.hab_status == ResponseValue.LOCKED


def test_sdp_jump_and_run_hab_locked() -> None:
    """Test SDP jump and run operation when HAB is locked.

    Verifies that the jump_and_run method correctly handles the case where the Hardware
    Assurance Boot (HAB) is locked. The test ensures that the operation completes
    successfully but the status code reflects the locked HAB state.

    :raises AssertionError: If any of the test assertions fail.
    """
    sdp = SDP(
        VirtualSDPInterface(
            VirtualDevice(
                respond_sequence=[CmdResponse(True, pack(">I", ResponseValue.LOCKED.tag))]  # type: ignore
            )
        )
    )
    assert sdp.is_opened
    assert sdp.jump_and_run(0x20000000)
    assert sdp.status_code == StatusCode.HAB_IS_LOCKED
    assert sdp.hab_status == ResponseValue.LOCKED


def test_sdp_send_data_errors() -> None:
    """Test SDP send data error handling functionality.

    This test verifies that the SDP _send_data method properly handles error responses
    from the device and sets appropriate status codes for different command types
    including WRITE_DCD, WRITE_CSF, and WRITE_FILE operations.
    """
    error_response = [
        CmdResponse(True, pack(">I", ResponseValue.UNLOCKED.tag)),
        CmdResponse(True, pack(">I", 0x12345678)),
    ]

    sdp = SDP(VirtualSDPInterface(VirtualDevice(respond_sequence=error_response.copy())))  # type: ignore

    virtual_device = sdp._interface.device
    assert isinstance(virtual_device, VirtualDevice)

    virtual_device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_DCD, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_DCD_FAILURE

    virtual_device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_CSF, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_CSF_FAILURE

    virtual_device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_FILE, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_IMAGE_FAILURE

    virtual_device.respond_sequence = error_response.copy()
    assert not sdp._send_data(CmdPacket(CommandTag.WRITE_DCD, 0, 0, 0), b"")
    assert sdp.status_code == StatusCode.WRITE_DCD_FAILURE


def test_sdp_read_args_errors() -> None:
    """Test SDP read and write argument validation errors.

    Verifies that SDP read_safe and write_safe methods properly validate
    input arguments and raise appropriate SdpError exceptions for invalid
    data formats and misaligned addresses.

    :raises SdpError: When invalid data format or address alignment is provided.
    """
    sdp = SDP(VirtualSDPInterface(VirtualDevice([])))  # type: ignore
    with pytest.raises(SdpError, match="Invalid data format"):
        sdp.read_safe(address=0, length=2, data_format=2)

    with pytest.raises(SdpError, match="not aligned"):
        sdp.read_safe(address=2, length=2, data_format=32)

    with pytest.raises(SdpError, match="Invalid data format"):
        sdp.write_safe(address=0, value=2, count=1, data_format=2)

    with pytest.raises(SdpError, match="not aligned"):
        sdp.write_safe(address=2, value=2, count=1, data_format=32)
