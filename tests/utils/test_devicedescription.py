#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Device Description utilities test suite.

This module contains comprehensive tests for the device description functionality
in SPSDK, covering various device interface types and description operations.
"""

from unittest.mock import MagicMock, patch

import pytest

import spsdk.utils.devicedescription as devicedescription
from spsdk.mboot.interfaces.usb import MbootUSBInterface


def test_uart_device_description() -> None:
    """Test UART device description string representation.

    Verifies that the UartDeviceDescription object correctly formats its string
    representation with port name and device type information.
    """
    formatted_output = "Port: some name\nType: some type"
    dev = devicedescription.UartDeviceDescription(name="some name", dev_type="some type")

    assert str(dev) == formatted_output


def test_usb_device_description() -> None:
    """Test USB device description string formatting.

    Validates that the USBDeviceDescription class correctly formats its string
    representation with all device information including vendor ID, product ID,
    path, name, and serial number.

    :raises AssertionError: If the formatted output doesn't match expected format.
    """
    formatted_output = (
        "my product - manufacturer X\n"
        "Vendor ID: 0x000a\n"
        "Product ID: 0x0014\n"
        "Path: some_path\n"
        "Path Hash: N/A\n"
        "Name: mboot device\n"
        "Serial number: 12345678"
    )
    dev = devicedescription.USBDeviceDescription(
        vid=10,
        pid=20,
        path="some_path",
        product_string="my product",
        manufacturer_string="manufacturer X",
        name="mboot device",
        serial="12345678",
    )

    assert str(dev) == formatted_output


def test_sdio_device_description() -> None:
    """Test SDIO device description string representation.

    Validates that the SDIODeviceDescription object correctly formats its string
    representation with vendor ID, product ID, and path information.

    :raises AssertionError: If the string representation doesn't match expected format.
    """
    formatted_output = "Vendor ID: 0x000a\nProduct ID: 0x0014\nPath: some_path\n"
    dev = devicedescription.SDIODeviceDescription(
        vid=10,
        pid=20,
        path="some_path",
    )

    assert str(dev) == formatted_output


# Test SIO device description is done by NXPDEVSCAN tests :-)


def test_str() -> None:
    """Test string representation of UartDeviceDescription.

    Verifies that the string representation of a UartDeviceDescription object
    matches the expected formatted output containing port name and device type.
    """
    formatted_output = "Port: some name\nType: some type"
    dev = devicedescription.UartDeviceDescription(name="some name", dev_type="some type")

    assert str(dev) == formatted_output


def test_repr() -> None:
    """Test the string representation of UartDeviceDescription.

    Verifies that the __repr__ method of UartDeviceDescription returns
    the expected formatted string containing the device name and type.
    """
    formatted_output = "UartDeviceDescription({'name': 'some name', 'dev_type': 'some type'})"
    dev = devicedescription.UartDeviceDescription(name="some name", dev_type="some type")

    assert repr(dev) == formatted_output


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
                "mimxrt1186",
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
def test_get_device_name2(vid: int, pid: int, expected_result: list[str]) -> None:
    """Test device name retrieval functionality using VID/PID pairs.

    Verifies that the USB device name search works correctly and returns
    the appropriate device names based on provided Vendor ID and Product ID.

    :param vid: Vendor ID to search for.
    :param pid: Product ID to search for.
    :param expected_result: List of expected device names that should be returned.
    """
    assert sorted(devicedescription.get_usb_device_name(vid, pid)) == sorted(expected_result)


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
                "mimxrt1186",
                "mimxrt1187",
                "mimxrt1189",
                "mwct2014s",
                "mwct2015s",
                "mwct2016s",
                "mwct2d16s",
                "mwct2d17s",
            ],
        ),
        (0x1FC9, 0x0135, []),
    ],
)
def test_get_device_name(vid: int, pid: int, expected_result: list[str]) -> None:
    """Test USB device name retrieval functionality.

    Verify that the device description search works correctly and returns
    the appropriate device names based on provided VID/PID combination.

    :param vid: USB Vendor ID to search for.
    :param pid: USB Product ID to search for.
    :param expected_result: List of expected device names that should be returned.
    """
    assert sorted(
        devicedescription.get_usb_device_name(vid, pid, MbootUSBInterface.get_devices())
    ) == sorted(expected_result)


def test_path_conversion() -> None:
    """Test USB path conversion functionality across different operating systems.

    Verifies that the convert_usb_path function correctly transforms platform-specific
    USB device paths into standardized formats for Windows, Linux, macOS, and unknown
    systems. Uses mocked platform detection to simulate different operating environments.
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

        linux_path = b""
        assert devicedescription.convert_usb_path(linux_path) == ""

    with patch("platform.system", MagicMock(return_value="Darwin")):
        mac_path = b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000"  # pylint: disable=line-too-long

        assert (
            devicedescription.convert_usb_path(mac_path)
            == "IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000"  # pylint: disable=line-too-long
        )

    with patch("platform.system", MagicMock(return_value="Unknown System")):
        path = b""

        assert devicedescription.convert_usb_path(path) == ""
