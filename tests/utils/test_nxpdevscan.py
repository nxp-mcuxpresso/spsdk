#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import platform
from typing import Optional
from unittest.mock import MagicMock, patch

import libusbsio
import pytest
from serial import Serial, SerialException
from serial.tools.list_ports_common import ListPortInfo

import spsdk.utils.devicedescription as devicedescription
import spsdk.utils.nxpdevscan as nds
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootConnectionError


def test_usb_device_search():
    """Test, that search method returns all NXP devices based on their VID.
    Default VID's so far are 0x1fc9, 0x15a2.
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


def test_usb_device_search_extended():
    """Verify search method returns all NXP devices based on their VID + all
    additional devices.
    Default VID's so far are 0x1fc9, 0x15a2
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


def mock_mb_scan_uart(port, timeout: int = 0):
    return True if port == "COM1" else False


def mock_sdp_read_status(self, *args, **kwargs):
    print("inside mock_sdp_read_status")
    retval = 1 if self._interface.device._device.port == "COM5" else None
    return retval


def mock_sdp_uart_init(self, port: str = None, timeout: int = 5000, baudrate: int = 115200):
    self._device = Serial(port=None, timeout=timeout / 1000, baudrate=baudrate)
    self._device.port = port
    self.expect_status = True


def mock_uboot_init(
    self,
    port: str,
    timeout: int = 1,
    baudrate: int = 115200,
    crc: bool = True,
    retries: int = 10,
    interrupt_autoboot: bool = True,
):
    self.port = port
    self._device = Serial(port=None, timeout=timeout, baudrate=baudrate)


def mock_uboot_is_serial_console_open(self):
    if self.port == "COM9":
        return True
    return False


list_port_info_mock = [
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
def test_uart_device_search():
    """Test, that search method returns all NXP Uart devices."""

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
def test_uart_device_search_no_scan():
    """Test, that search method returns all NXP Uart devices without scanning."""
    devices = nds.search_nxp_uart_devices(scan=False)
    assert len(devices) == 4


@pytest.mark.skipif(platform.system() != "Darwin", reason="This test is only for macOS")
@patch(
    "spsdk.utils.nxpdevscan.comports",
    MagicMock(return_value=[ListPortInfo(device="/dev/cu.usbmodem")]),
)
def test_uart_device_search_no_scan_macos():
    """Test, that search method returns all NXP Uart devices on macOS without scanning."""
    devices = nds.search_nxp_uart_devices(scan=False)
    assert len(devices) == 1
    assert devices[0].name == "/dev/cu.usbmodem"


# following mock functions are only for `test_sdio_device_search usage`
class mockSdio:
    def __init__(self, path: str = None) -> None:
        """Initialize the SDIO interface object.

        :raises McuBootConnectionError: when the path is empty
        """
        super().__init__()

        class SdioDevice:
            def __init__(self, _path) -> None:
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


def test_sdio_device_search():
    """Test, that search method returns all NXP SDIO devices."""

    test = mockSdio("/dev/mcu-sdio")
    result = [
        devicedescription.SDIODeviceDescription(0x0471, 0x0209, "/dev/mcu-sdio"),
    ]
    with patch("spsdk.utils.nxpdevscan.MbootSdioInterface.scan", MagicMock(return_value=[test])):
        devices = nds.search_nxp_sdio_devices()

        assert len(devices) == len(result)

        for dev, res in zip(devices, result):
            assert str(dev) == str(res)


def test_sdio_device_search_no_device_found():
    """Test, that search method returns all NXP SDIO devices."""

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
def test_get_device_name(vid, pid, expected_result):
    """Verify search works and returns appropriate name based on VID/PID"""
    assert sorted(devicedescription.get_usb_device_name(vid, pid)) == sorted(expected_result)


def test_path_conversion():
    """Verify, that path gets converted properly."""
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
        mac_path = b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000"

        assert (
            devicedescription.convert_usb_path(mac_path)
            == "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000"
        )


PATH_BY_SYSTEM = {
    "Windows": (b"some_path", "SOME_PATH", "0e3ac799"),
    "Linux": (b"000A:000B:00", "10#11", "87c906f3"),
    "Darwin": (
        b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",
        "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",
        "80157ec4",
    ),
}


def mock_libusbsio_GetDeviceInfo(self, dev: int):
    """MagicMock override function to return information."""
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
def test_sio_device_search():
    """Test, that search method returns all NXP SIO devices."""

    def get_return(path):
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


def mock_libusbsio_GetNumPorts(self, vidpids=None):
    """Try to get number of ports from LIBUSBSIO, but it fails."""
    raise libusbsio.LIBUSBSIO_Exception("Test Fail")


@patch("libusbsio.LIBUSBSIO.GetNumPorts", mock_libusbsio_GetNumPorts)
def test_sio_device_search_fail():
    """Test, that search method returns all NXP SIO devices and its fails."""
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

    def __init__(self, port: Optional[str] = None, baudrate=9600, timeout=None, write_timeout=None):
        if port == "COM1":
            raise SerialException("PermissionError")
        self.is_open = False

    def open(self):
        self.is_open = True

    def close(self):
        self.is_open = False

    def reset_input_buffer(self):
        pass

    def reset_output_buffer(self):
        pass


def mock_ping(self):
    pass


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="macOS is not supported due to filtering of devices"
)
@patch("spsdk.utils.interfaces.device.serial_device.Serial", PermissionTestMockSerial)
@patch("spsdk.mboot.interfaces.uart.MbootUARTInterface._ping", mock_ping)
@patch("spsdk.utils.nxpdevscan.comports", MagicMock(return_value=list_port_info_mock))
def test_serial_device_permission_error():
    devices = nds.search_nxp_uart_devices(scan_uboot=False)
    result = [
        devicedescription.UartDeviceDescription(name="COM5", dev_type="mboot device"),
        devicedescription.UartDeviceDescription(name="COM28", dev_type="mboot device"),
        devicedescription.UartDeviceDescription(name="COM9", dev_type="mboot device"),
    ]
    assert len(devices) == len(result)

    for dev, res in zip(devices, result):
        assert str(dev) == str(res)
