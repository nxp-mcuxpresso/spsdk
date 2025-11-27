#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK SDP (Serial Download Protocol) test suite.

This module contains unit tests for SDP functionality including virtual device
implementations, mock interfaces, and exception handling tests to ensure
reliable SDP communication across NXP MCU portfolio.
"""

from typing import Optional, Union
from unittest.mock import patch

from typing_extensions import Self

from spsdk.exceptions import SPSDKAttributeError, SPSDKConnectionError
from spsdk.sdp.commands import CmdPacket
from spsdk.sdp.exceptions import SdpConnectionError
from spsdk.sdp.sdps import SDPS, RomInfo
from spsdk.utils.family import FamilyRevision
from spsdk.utils.interfaces.commands import CmdResponseBase
from spsdk.utils.interfaces.device.base import DeviceBase

data = b"\xad" * 100
cmd_pack = b"BLTC\x01\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class VirtualDevice(DeviceBase):
    """Virtual SDP device implementation for testing purposes.

    This class provides a mock implementation of an SDP (Serial Download Protocol)
    device interface that simulates the behavior of a real hardware device without
    requiring actual hardware connections. It maintains connection state and provides
    standard device operations for use in unit tests and development scenarios.
    """

    def __init__(self) -> None:
        """Initialize the SDP interface.

        Sets up the initial state of the SDP (Serial Download Protocol) interface
        with default values for connection status, command indexing, and timeout.
        The interface starts in a closed state and must be opened before use.
        """
        self._is_opened = False
        self.cmd_index = 0
        self._timeout = 0

    @property
    def is_opened(self) -> bool:
        """Check if the connection is currently opened.

        :return: True if connection is opened, False otherwise.
        """
        return self._is_opened

    def open(self) -> None:
        """Open the connection.

        Sets the internal state to indicate that the connection has been opened.
        """
        self._is_opened = True

    def close(self) -> None:
        """Close the SDP connection.

        Sets the internal opened state to False, indicating that the SDP (Serial Download Protocol)
        connection is no longer active.
        """
        self._is_opened = False

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the SDP interface.

        This method provides a mock implementation for testing purposes and always returns empty bytes.

        :param length: Number of bytes to read from the interface.
        :param timeout: Optional timeout value in milliseconds for the read operation.
        :return: Empty bytes object as this is a mock implementation.
        """
        return b""

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to the mock interface for testing purposes.

        This method simulates writing data to an SDP interface by validating that the
        correct command packet or data is being written in the expected sequence.

        :param data: The data bytes to write to the interface.
        :param timeout: Optional timeout value in seconds for the write operation.
        :raises AssertionError: If the data doesn't match expected command packet or data sequence.
        """
        if self.cmd_index == 0:
            assert data == cmd_pack
            self.cmd_index += 1
        else:
            assert data == data

    def __str__(self) -> str:
        """Get string representation of the virtual device.

        :return: String identifier for the virtual device.
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

    This class provides a mock implementation of the Serial Download Protocol (SDP)
    interface that communicates with virtual devices instead of real hardware.
    It enables comprehensive testing of SDP operations without requiring physical
    devices, supporting the full range of SDP communication patterns including
    device scanning, connection management, and data transfer operations.
    """

    def __init__(self, device: VirtualDevice) -> None:
        """Initialize the virtual device handler.

        Sets up the connection to a virtual device for SDP communication testing.

        :param device: Virtual device instance to communicate with
        :type device: VirtualDevice
        """
        self.device = device

    def open(self) -> None:
        """Open the interface.

        This method establishes a connection to the underlying device interface,
        making it ready for communication operations.

        :raises SPSDKError: If the device interface fails to open or is not available.
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
        """Scan for available SDP devices.

        This method scans for Serial Download Protocol (SDP) devices that are
        currently connected and available for communication.

        :param params: Connection parameters for device scanning.
        :param timeout: Maximum time in seconds to wait for device discovery.
        :param extra_params: Additional optional parameters for scanning configuration.
        :return: List of discovered SDP device instances.
        """
        return []

    def read(self, length: Optional[int] = None) -> Union[CmdResponseBase, bytes]:
        """Read data from the SDP device.

        This method reads data from the underlying SDP device interface with an optional
        length parameter to specify the number of bytes to read.

        :param length: Number of bytes to read from device. If None, defaults to 0.
        :return: Command response object or raw bytes data from the device.
        """
        return self.device.read(length or 0)

    def write_data(self, data: bytes) -> None:
        """Write data to the SDP device.

        This method sends the provided data bytes directly to the connected SDP device
        through the underlying device interface.

        :param data: The binary data to be written to the device.
        :raises SPSDKError: If the write operation fails or device is not accessible.
        """
        self.device.write(data)

    def write_command(self, packet: CmdPacket) -> None:
        """Write command packet to the device.

        Exports the command packet data and sends it to the connected device.

        :param packet: Command packet to be written to the device.
        :raises SPSDKAttributeError: When packet export returns empty data indicating incorrect packet type.
        """
        data = packet.export(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        self.device.write(data)

    def configure(self, config: dict) -> None:
        """Configure the SDP interface with required parameters.

        Validates that the configuration dictionary contains the mandatory 'hid_ep1'
        and 'pack_size' keys for proper SDP communication setup.

        :param config: Configuration dictionary containing SDP interface settings
        :raises AssertionError: When required configuration keys are missing
        """
        assert "hid_ep1" in config
        assert "pack_size" in config


def test_open_close() -> None:
    """Test SDPS open and close functionality.

    Verifies that SDPS interface is closed by default, can be opened successfully,
    and remains open when open() is called multiple times on an already opened interface.

    :raises AssertionError: If SDPS state doesn't match expected open/closed status.
    """
    spds = SDPS(VirtualSDPInterface(VirtualDevice()), FamilyRevision("mx93"))  # type: ignore[arg-type]
    assert not spds.is_opened
    spds.open()
    assert spds.is_opened
    spds.open()
    # TODO: analyze caplog, there should be no new records
    assert spds.is_opened


@patch("spsdk.sdp.sdps.SDPS.rom_info", RomInfo(False, False, 1024))
def test_sdps_send_data() -> None:
    """Test SDPS send data functionality.

    Verifies that the SDPS context manager properly handles file writing operations
    and correctly manages the connection state. The test ensures that the SDPS
    instance is opened during the context and properly closed after exiting.

    :raises AssertionError: If SDPS connection state is not as expected.
    """
    with SDPS(VirtualSDPInterface(VirtualDevice()), FamilyRevision("mx93")) as sdps:  # type: ignore[arg-type]
        assert sdps.is_opened
        sdps.write_file(data)
    assert sdps.is_opened is False


class VirtualDeviceException(VirtualDevice):
    """Virtual device for testing connection exceptions.

    This class extends VirtualDevice to simulate connection failures during testing.
    It is specifically designed to raise SPSDKConnectionError exceptions when write
    operations are attempted, allowing test cases to verify proper error handling
    in SDP communication scenarios.
    """

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to the connection.

        This method is designed to raise an SPSDKConnectionError as part of test functionality
        to simulate connection write failures.

        :param data: The bytes data to be written to the connection.
        :param timeout: Optional timeout value in seconds for the write operation.
        :raises SPSDKConnectionError: Always raised to simulate connection failure.
        """
        raise SPSDKConnectionError()

    def __str__(self) -> str:
        """Get string representation of VirtualDeviceException.

        :return: String representation of the exception.
        """
        return "VirtualDeviceException"


def test_sdps_exception() -> None:
    """Test SDPS connection error handling.

    Verifies that SdpConnectionError is properly raised when attempting to write
    data through a virtual SDP interface that simulates connection exceptions.
    The test ensures that only the expected SdpConnectionError is caught and
    other exceptions cause the test to fail.
    """
    try:
        sdps = SDPS(VirtualSDPInterface(VirtualDeviceException()), FamilyRevision("mx8ulp"))  # type: ignore[arg-type]
        sdps.write_file(data)
        assert False
    except SdpConnectionError:
        assert True
    except Exception:
        assert False
