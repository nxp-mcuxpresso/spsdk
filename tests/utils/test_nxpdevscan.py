#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK NXP device scanning functionality tests.

This module contains comprehensive tests for the nxpdevscan module,
which provides device discovery and scanning capabilities across
different communication interfaces (USB, UART, SDIO, SIO).
The tests cover device detection, error handling, platform-specific
behavior, and permission scenarios for NXP device scanning functionality.
"""

import platform
from typing import Any, Optional
from unittest.mock import MagicMock, patch

import libusbsio
import pytest
from serial import Serial, SerialException
from serial.tools.list_ports_common import ListPortInfo

import spsdk.utils.devicedescription as devicedescription
import spsdk.utils.nxpdevscan as nds
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootConnectionError


def test_usb_device_search() -> None:
    """Test USB device search functionality for NXP devices.

    Verifies that the search method correctly identifies and returns only NXP devices
    based on their Vendor IDs (0x1fc9, 0x15a2) from a mixed list of USB devices.
    Uses mocked USB enumeration to test filtering logic without requiring actual hardware.
    """
    test_vector = [
        {
            "vendor_id": 0x0001,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x15,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x1FC9,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x15A2,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
    ]
    result = [
        devicedescription.USBDeviceDescription(0x1FC9, 0, "", "", "", "", ""),
        devicedescription.USBDeviceDescription(0x15A2, 0, "", "", "", "", ""),
    ]

    with patch("libusbsio.LIBUSBSIO.HIDAPI_Enumerate", MagicMock(return_value=test_vector)):
        devices = nds.search_nxp_usb_devices()

        assert len(devices) == len(result)

        for dev, res in zip(devices, result):
            assert str(dev) == str(res)


def test_usb_device_search_extended() -> None:
    """Test USB device search with extended vendor ID filtering.

    Verifies that the search method correctly returns all NXP devices based on their
    default vendor IDs (0x1fc9, 0x15a2) plus any additional devices matching the
    provided vendor ID list. The test uses a mock USB device enumeration to simulate
    various devices and validates the filtering behavior.

    :param: This test function takes no parameters.
    """
    test_vector = [
        {
            "vendor_id": 0x1FC9,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x0001,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x15,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x1FC9,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x0002,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
        {
            "vendor_id": 0x15A2,
            "product_id": 0,
            "path": b"",
            "manufacturer_string": "",
            "product_string": "",
            "serial_number": "",
        },
    ]
    result = [
        devicedescription.USBDeviceDescription(0x1FC9, 0, "", "", "", "", ""),
        devicedescription.USBDeviceDescription(0x1FC9, 0, "", "", "", "", ""),
        devicedescription.USBDeviceDescription(0x0002, 0, "", "", "", "", ""),
        devicedescription.USBDeviceDescription(0x15A2, 0, "", "", "", "", ""),
    ]
    with patch("libusbsio.LIBUSBSIO.HIDAPI_Enumerate", MagicMock(return_value=test_vector)):
        devices = nds.search_nxp_usb_devices([0x2])

        assert len(devices) == len(result)

        for dev, res in zip(devices, result):
            assert str(dev) == str(res)


# following mock functions are only for `test_uart_device_search usage`


def mock_mb_scan_uart(port: str, timeout: int = 0) -> bool:
    """Mock UART scanning function for testing purposes.

    Simulates the behavior of scanning a UART port for mboot communication.
    This mock function returns True only for COM1 port to enable predictable
    testing scenarios.

    :param port: UART port identifier to scan (e.g., "COM1", "COM2").
    :param timeout: Timeout value in seconds for the scan operation.
    :return: True if port is COM1, False otherwise.
    """
    return bool(port == "COM1")


def mock_sdp_read_status(self: Any, *args: Any, **kwargs: Any) -> Optional[int]:
    """Mock SDP read status operation for testing purposes.

    This method simulates the SDP (Serial Download Protocol) read status functionality
    by returning a predefined status value based on the device port configuration.
    It's designed for use in unit tests to avoid actual hardware communication.

    :param self: Instance of the mock object containing interface and device information.
    :param args: Variable length argument list (unused in this implementation).
    :param kwargs: Arbitrary keyword arguments (unused in this implementation).
    :return: Status value 1 if device port is "COM5", None otherwise.
    """
    print("inside mock_sdp_read_status")
    retval = 1 if self._interface.device._device.port == "COM5" else None
    return retval


def mock_sdp_uart_init(
    self: Any, port: Optional[str] = None, timeout: int = 5000, baudrate: int = 115200
) -> None:
    """Mock initialization of SDP UART interface for testing purposes.

    Creates a mock Serial device instance with specified configuration parameters
    for use in unit tests and development scenarios.

    :param port: Serial port identifier, defaults to None for mock testing.
    :param timeout: Communication timeout in milliseconds.
    :param baudrate: Serial communication baud rate.
    """
    self._device = Serial(port=None, timeout=timeout / 1000, baudrate=baudrate)
    self._device.port = port
    self.expect_status = True


def mock_uboot_init(
    self: Any,
    port: str,
    timeout: int = 1,
    baudrate: int = 115200,
    crc: bool = True,
    retries: int = 10,
    interrupt_autoboot: bool = True,
) -> None:
    """Mock initialization for U-Boot interface.

    Initializes a mock U-Boot interface with specified serial communication parameters
    for testing purposes. Creates a Serial device instance without opening the connection.

    :param port: Serial port identifier for the connection.
    :param timeout: Communication timeout in seconds.
    :param baudrate: Serial communication baud rate.
    :param crc: Enable CRC checking for data integrity.
    :param retries: Number of retry attempts for failed operations.
    :param interrupt_autoboot: Whether to interrupt U-Boot autoboot sequence.
    """
    self.port = port
    self._device = Serial(port=None, timeout=timeout, baudrate=baudrate)


def mock_uboot_is_serial_console_open(self: Any) -> bool:
    """Mock method to check if U-Boot serial console is open.

    This mock implementation simulates the behavior of checking whether a U-Boot
    serial console connection is open on a specific port. Returns True only for
    COM9 port to facilitate testing scenarios.

    :param self: Instance of the mock class containing port information.
    :return: True if the port is COM9, False otherwise.
    """
    if self.port == "COM9":
        return True
    return False


list_port_info_mock: list[ListPortInfo] = [
    ListPortInfo(device="COM1"),
    ListPortInfo(device="COM5"),
    ListPortInfo(device="COM28"),
    ListPortInfo(device="COM9"),
]


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="macOS is not supported due to filtering of devices"
)
@patch("spsdk.utils.nxpdevscan.MbootUARTInterface.scan", mock_mb_scan_uart)
@patch("spsdk.utils.nxpdevscan.SDP.read_status", mock_sdp_read_status)
@patch(
    "spsdk.utils.interfaces.device.serial_device.SerialDevice.__init__",
    mock_sdp_uart_init,
)
@patch("spsdk.utils.nxpdevscan.comports", MagicMock(return_value=list_port_info_mock))
@patch("spsdk.uboot.uboot.UbootSerial.__init__", mock_uboot_init)
@patch("spsdk.uboot.uboot.UbootSerial.is_serial_console_open", mock_uboot_is_serial_console_open)
def test_uart_device_search() -> None:
    """Test that search method returns all NXP UART devices.

    Verifies that the nxpdevscan search functionality correctly identifies and returns
    all available NXP UART devices with proper device descriptions including COM port
    names and device types (mboot device, SDP device, U-Boot console).

    :raises AssertionError: If the number of found devices doesn't match expected count
                           or if device descriptions don't match expected format.
    """

    result = [
        devicedescription.UartDeviceDescription(name="COM1", dev_type="mboot device"),
        devicedescription.UartDeviceDescription(name="COM5", dev_type="SDP device"),
        devicedescription.UartDeviceDescription(name="COM9", dev_type="U-Boot console"),
    ]

    devices = nds.search_nxp_uart_devices()

    assert len(devices) == len(result)

    for dev, res in zip(devices, result):
        assert str(dev) == str(res)


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="macOS is not supported due to filtering of devices"
)
@patch("spsdk.utils.nxpdevscan.comports", MagicMock(return_value=list_port_info_mock))
def test_uart_device_search_no_scan() -> None:
    """Test that search method returns all NXP UART devices without scanning.

    Verifies that the search_nxp_uart_devices function returns exactly 4 devices
    when called with scan=False parameter, ensuring the method works correctly
    without performing an actual device scan.

    :raises AssertionError: If the number of returned devices is not 4.
    """
    devices = nds.search_nxp_uart_devices(scan=False)
    assert len(devices) == 4


@pytest.mark.skipif(platform.system() != "Darwin", reason="This test is only for macOS")
@patch(
    "spsdk.utils.nxpdevscan.comports",
    MagicMock(return_value=[ListPortInfo(device="/dev/cu.usbmodem")]),
)
def test_uart_device_search_no_scan_macos() -> None:
    """Test that search method returns all NXP UART devices on macOS without scanning.

    Validates the behavior of the search_nxp_uart_devices function when called
    with scan=False on macOS systems, ensuring it returns the expected device
    list without performing an active scan.

    :raises AssertionError: If the returned device list doesn't match expected results.
    """
    devices = nds.search_nxp_uart_devices(scan=False)
    assert len(devices) == 1
    assert devices[0].name == "/dev/cu.usbmodem"


# following mock functions are only for `test_sdio_device_search usage`
class mockSdio:
    """Mock SDIO interface for testing purposes.

    This class simulates an SDIO (Secure Digital Input Output) interface
    to enable testing of SDIO-related functionality without requiring
    actual hardware connections. It creates a mock device with predefined
    VID/PID values and basic configuration parameters.
    """

    def __init__(self, path: Optional[str] = None) -> None:
        """Initialize the SDIO interface object.

        Creates an SDIO interface with the specified device path and initializes
        internal device configuration with default VID/PID values.

        :param path: Path to the SDIO device, required for connection
        :raises McuBootConnectionError: When the path is empty or None
        """
        super().__init__()

        class SdioDevice:
            """SPSDK SDIO Device Interface.

            This class provides an interface for communicating with SDIO devices
            in the SPSDK ecosystem, managing device connection parameters and
            communication settings for secure provisioning operations.
            """

            def __init__(self, _path: Optional[str]) -> None:
                self._opened = False
                # Temporarily use hard code until there is a way to retrieve VID/PID
                self.vid = 0x0471
                self.pid = 0x0209
                self.timeout = 2000
                if path is None:
                    raise McuBootConnectionError("No SDIO device path")
                self.path = _path
                self.is_blocking = False

        self.device = SdioDevice(path)


def test_sdio_device_search() -> None:
    """Test that the search method returns all NXP SDIO devices.

    This test verifies the functionality of the SDIO device search by mocking
    an SDIO interface and ensuring the search returns the expected device
    descriptions with correct vendor ID, product ID, and device path.
    """

    test = mockSdio("/dev/mcu-sdio")
    result = [
        devicedescription.SDIODeviceDescription(0x0471, 0x0209, "/dev/mcu-sdio"),
    ]
    with patch("spsdk.utils.nxpdevscan.MbootSdioInterface.scan", MagicMock(return_value=[test])):
        devices = nds.search_nxp_sdio_devices()

        assert len(devices) == len(result)

        for dev, res in zip(devices, result):
            assert str(dev) == str(res)


def test_sdio_device_search_no_device_found() -> None:
    """Test that SDIO device search returns empty list when no devices are found.

    This test verifies the behavior of the search_nxp_sdio_devices function
    when the underlying SDIO interface scan returns an empty list, ensuring
    the search method properly handles the case where no NXP SDIO devices
    are detected.
    """

    result = [
        devicedescription.SDIODeviceDescription(0x0471, 0x0209, ""),
    ]
    with patch("spsdk.utils.nxpdevscan.MbootSdioInterface.scan", MagicMock(return_value=[])):
        devices = nds.search_nxp_sdio_devices()
        assert len(devices) != len(result)


@pytest.mark.parametrize(
    "vid, pid, expected_result",
    [
        (0x1111, 0x2222, []),
        (
            0x15A2,
            0x0073,
            [
                "mcxc141",
                "mcxc142",
                "mcxc143",
                "mcxc144",
                "mcxc242",
                "mcxc243",
                "mcxc244",
                "mcxc443",
                "mcxc444",
                "mimxrt1010",
                "mimxrt1015",
                "mimxrt1020",
                "mimxrt1024",
                "mimxrt1040",
                "mimxrt1043",
                "mimxrt1046",
                "mimxrt1050",
                "mimxrt1060",
                "mimxrt1064",
                "mimxrt1165",
                "mimxrt1166",
                "mimxrt1171",
                "mimxrt1172",
                "mimxrt1173",
                "mimxrt1175",
                "mimxrt1176",
                "mimxrt1181",
                "mimxrt1182",
                "mimxrt1187",
                "mimxrt1186",
                "mimxrt1189",
                "mwct2014s",
                "mwct2015s",
                "mwct2016s",
                "mwct2d16s",
                "mwct2d17s",
            ],
        ),
        (0x1FC9, 0x0135, ["mimxrt1040", "mimxrt1043", "mimxrt1046", "mimxrt1060", "mimxrt1064"]),
    ],
)
def test_get_device_name(vid: int, pid: int, expected_result: list[str]) -> None:
    """Test that USB device name retrieval works correctly for given VID/PID combinations.

    Verifies that the devicedescription.get_usb_device_name function returns the expected
    device names when provided with specific Vendor ID and Product ID values.

    :param vid: USB Vendor ID to search for.
    :param pid: USB Product ID to search for.
    :param expected_result: List of expected device names that should be returned.
    """
    assert sorted(devicedescription.get_usb_device_name(vid, pid)) == sorted(expected_result)


def test_path_conversion() -> None:
    """Test USB device path conversion across different operating systems.

    Verifies that the convert_usb_path function properly converts platform-specific
    USB device paths to standardized formats for Windows, Linux, and macOS systems.
    The test uses mocked platform detection to simulate different operating systems
    and validates the expected path transformations for each platform.
    """
    with patch("platform.system", MagicMock(return_value="Windows")):
        win_path = (
            b"\\\\?\\hid#vid_1fc9&pid_0130#6&1625c75b&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}"
        )
        assert (
            devicedescription.convert_usb_path(win_path)
            == "HID\\VID_1FC9&PID_0130\\6&1625C75B&0&0000"
        )

    with patch("platform.system", MagicMock(return_value="Linux")):
        linux_path = b"000A:000B:00"

        assert devicedescription.convert_usb_path(linux_path) == "10#11"

    with patch("platform.system", MagicMock(return_value="Darwin")):
        mac_path = b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000"  # pylint: disable=line-too-long

        assert (
            devicedescription.convert_usb_path(mac_path)
            == "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000"  # pylint: disable=line-too-long
        )


PATH_BY_SYSTEM = {
    "Windows": (b"some_path", "SOME_PATH", "0e3ac799"),
    "Linux": (b"000A:000B:00", "10#11", "87c906f3"),
    "Darwin": (
        b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",  # pylint: disable=line-too-long
        "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",  # pylint: disable=line-too-long
        "80157ec4",
    ),
}


def mock_libusbsio_GetDeviceInfo(self, dev: int) -> libusbsio.LIBUSBSIO.HIDAPI_DEVICE_INFO_T:  # type: ignore
    """Mock override function to return LIBUSBSIO device information.

    This method simulates the behavior of the actual LIBUSBSIO GetDeviceInfo function
    for testing purposes. It creates and returns a mock device info structure with
    predefined values including vendor ID, product ID, and other device attributes.

    :param dev: Device index (must be 0 for this mock implementation).
    :raises AssertionError: If dev parameter is not equal to 0.
    :return: Mock LIBUSBSIO device information structure with predefined test values.
    """
    assert dev == 0
    sio_info = libusbsio.LIBUSBSIO.HIDAPI_DEVICE_INFO_T()
    sio_info.vendor_id = 10
    sio_info.product_id = 20
    sio_info.product_string = "my product"
    sio_info.manufacturer_string = "manufacturer X"
    sio_info.serial_number = "sio device"
    sio_info.interface_number = 5
    sio_info.release_number = 125
    sio_info.path = PATH_BY_SYSTEM[platform.system()][0]

    return sio_info


@patch("libusbsio.LIBUSBSIO.GetNumPorts", MagicMock(return_value=1))
@patch("libusbsio.LIBUSBSIO.GetDeviceInfo", mock_libusbsio_GetDeviceInfo)
def test_sio_device_search() -> None:
    """Test that the search method returns all NXP SIO devices.

    This test verifies the functionality of the nxpdevscan module's ability to
    discover and return NXP SIO (Serial Input/Output) devices. It mocks the
    platform system detection and validates that exactly one device is found
    with the expected string representation format.

    :raises AssertionError: If the number of discovered devices is not 1 or if
        the device string representation doesn't match expected format.
    """

    def get_return(path: tuple[bytes, str, str]) -> str:
        """Generate mock LIBUSBSIO device information string.

        Creates a formatted string containing mock device information for LIBUSBSIO
        devices used in testing scenarios. The string includes vendor/product IDs,
        device path, serial number, and other device attributes.

        :param path: Tuple containing device path information as (bytes, string path, path hash).
        :return: Formatted string with mock LIBUSBSIO device information.
        """
        return (
            "LIBUSBSIO - manufacturer X, my product\n"
            "Vendor ID: 0x000a\n"
            "Product ID: 0x0014\n"
            f"Path: {path[1]}\n"
            f"Path Hash: {path[2]}\n"
            "Serial number: sio device\n"
            "Interface number: 5\n"
            "Release number: 125"
        )

    system = platform.system()
    with patch("platform.system", MagicMock(return_value=system)):
        devices = nds.search_libusbsio_devices()
        assert len(devices) == 1
        assert str(devices[0]) == get_return(PATH_BY_SYSTEM[system])


def mock_libusbsio_GetNumPorts(self, vidpids=None) -> None:  # type: ignore #pylint: disable=missing-type-doc
    """Mock method that simulates LIBUSBSIO port enumeration failure.

    This method is used in testing to simulate the scenario where LIBUSBSIO
    fails to retrieve the number of available ports, allowing verification
    of error handling behavior.

    :param vidpids: Vendor ID and Product ID pairs to filter devices (unused in mock).
    :raises libusbsio.LIBUSBSIO_Exception: Always raised to simulate failure condition.
    """
    raise libusbsio.LIBUSBSIO_Exception("Test Fail")


@patch("libusbsio.LIBUSBSIO.GetNumPorts", mock_libusbsio_GetNumPorts)
def test_sio_device_search_fail() -> None:
    """Test that the search method for NXP SIO devices properly handles failure cases.

    This test verifies that the search_libusbsio_devices() function raises an SPSDKError
    when it encounters an error condition during device scanning.

    :raises SPSDKError: Expected exception when device search fails.
    """
    with pytest.raises(SPSDKError):
        nds.search_libusbsio_devices()


# def mock_uart_init_permission_error(
#     self,
#     port: Optional[str] = None,
#     timeout: Optional[int] = None,
#     baudrate: Optional[int] = None,
# ):
#     if port == "COM1":
#         raise SPSDKPermissionError()
#     self._device = Serial(port=None, timeout=timeout / 1000, baudrate=baudrate)


class PermissionTestMockSerial:
    """Mock serial connection for permission testing.

    This class simulates a serial connection that throws permission errors
    for specific ports (COM1) and provides basic connection state management
    for testing SPSDK device scanning functionality.
    """

    def __init__(
        self,
        port: Optional[str] = None,
        baudrate: int = 9600,
        timeout: Optional[int] = None,
        write_timeout: Optional[int] = None,
    ):
        """Initialize mock serial connection for testing.

        Creates a mock serial connection that simulates permission errors for COM1 port
        and tracks connection state for testing purposes.

        :param port: Serial port name, defaults to None
        :param baudrate: Communication baud rate, defaults to 9600
        :param timeout: Read timeout in seconds, defaults to None
        :param write_timeout: Write timeout in seconds, defaults to None
        :raises SerialException: When attempting to connect to COM1 port
        """
        if port == "COM1":
            raise SerialException("PermissionError")
        self.is_open = False

    def open(self) -> None:
        """Open the device connection.

        Sets the internal state to indicate that the device connection is open
        and ready for communication.

        :raises SPSDKError: If the device is already open or cannot be opened.
        """
        self.is_open = True

    def close(self) -> None:
        """Close the connection and mark it as closed.

        Sets the is_open flag to False to indicate that the connection
        is no longer active.
        """
        self.is_open = False

    def reset_input_buffer(self) -> None:
        """Reset the input buffer to clear any pending data.

        This method clears any data that may be buffered in the input stream,
        ensuring a clean state for subsequent operations.
        """

    def reset_output_buffer(self) -> None:
        """Reset the output buffer to clear any pending data.

        This method clears any data that may be buffered in the output stream,
        ensuring a clean state for subsequent operations.
        """


def mock_ping(self) -> None:  # type: ignore
    """Mock implementation of ping functionality for testing purposes.

    This method provides a no-operation mock implementation that can be used
    in unit tests to replace actual ping operations without performing real
    network connectivity checks.
    """


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="macOS is not supported due to filtering of devices"
)
@patch("spsdk.utils.interfaces.device.serial_device.Serial", PermissionTestMockSerial)
@patch("spsdk.mboot.interfaces.uart.MbootUARTInterface._ping", mock_ping)
@patch("spsdk.utils.nxpdevscan.comports", MagicMock(return_value=list_port_info_mock))
def test_serial_device_permission_error() -> None:
    """Test serial device permission error handling.

    This test verifies that the UART device scanning functionality works correctly
    when permission errors might occur during device access. It compares the
    scanned devices against expected mboot devices on specific COM ports.

    :raises AssertionError: If the number of found devices doesn't match expected count
                           or if device descriptions don't match expected values.
    """
    devices = nds.search_nxp_uart_devices(scan_uboot=False)
    result = [
        devicedescription.UartDeviceDescription(name="COM5", dev_type="mboot device"),
        devicedescription.UartDeviceDescription(name="COM28", dev_type="mboot device"),
        devicedescription.UartDeviceDescription(name="COM9", dev_type="mboot device"),
    ]
    assert len(devices) == len(result)

    for dev, res in zip(devices, result):
        assert str(dev) == str(res)
