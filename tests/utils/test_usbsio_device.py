#!/usr/bin/env python
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USB-SIO device configuration testing module.

This module contains unit tests for USB-SIO device configuration parsing
functionality, ensuring proper validation of configuration strings and
error handling for invalid inputs.
"""

from typing import Any
from unittest.mock import MagicMock

import pytest

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.interfaces.device.usbsio_device import (
    UsbSioConfig,
    UsbSioI2CDevice,
    UsbSioSPIDevice,
)


@pytest.mark.parametrize(
    "interface, config, usb_cfg, port_num, args, kwargs",
    [
        ("i2c", "usb,0x1fc9:0x0143,i2c", "0x1fc9:0x0143", 0, [], {}),
        ("i2c", "usb,0x1fc9:0x0143,i2c,16,100,1,7", "0x1fc9:0x0143", 0, [16, 100, 1, 7], {}),
        ("i2c", "0x1fc9:0x0143,i2c", "0x1fc9:0x0143", 0, [], {}),
        (
            "i2c",
            "usb,HID\\VID_1FC9&PID_0143&MI_06\\7&135EFA0E&0&0000,i2c,16,100,1,7",
            "HID\\VID_1FC9&PID_0143&MI_06\\7&135EFA0E&0&0000",
            0,
            [16, 100, 1, 7],
            {},
        ),
        (
            "i2c",
            "i2c,16,100,1,7",
            None,
            0,
            [16, 100, 1, 7],
            {},
        ),
        (
            "spi",
            "spi,0,15,1000,1,1,1,7",
            None,
            0,
            [0, 15, 1000, 1, 1, 1, 7],
            {},
        ),
        (
            "spi",
            "spi,ssel_port=0,ssel_pin=15,speed_khz=1000,cpol=1,cpha=1,nirq_port=1,nirq_pin=7",
            None,
            0,
            [],
            {
                "ssel_port": 0,
                "ssel_pin": 15,
                "speed_khz": 1000,
                "cpol": 1,
                "cpha": 1,
                "nirq_port": 1,
                "nirq_pin": 7,
            },
        ),
        (
            "spi",
            "spi,0,15,1000,cpol=1,cpha=1,nirq_port=1,nirq_pin=7",
            None,
            0,
            [0, 15, 1000],
            {
                "cpol": 1,
                "cpha": 1,
                "nirq_port": 1,
                "nirq_pin": 7,
            },
        ),
        ("i2c", "usb,0x1fc9:0x0143,i2c5", "0x1fc9:0x0143", 5, [], {}),
        ("i2c", "i2c", None, 0, [], {}),
        ("i2c", "i2c1,0x10", None, 1, [16], {}),
    ],
)
def test_libusbsio_parse_valid_configuration_string(
    interface: str,
    config: str,
    usb_cfg: str | None,
    port_num: int,
    args: list[int | str],
    kwargs: dict[str, Any],
) -> None:
    """Test parsing of valid USBSIO configuration strings.

    Validates that UsbSioConfig.from_config_string correctly parses valid
    configuration strings and produces expected configuration objects with
    proper USB configuration, port number, interface arguments and keyword arguments.

    :param interface: Interface type identifier for the USBSIO device.
    :param config: Configuration string to be parsed.
    :param usb_cfg: Expected USB configuration string after parsing.
    :param port_num: Expected port number after parsing.
    :param args: Expected list of interface arguments after parsing.
    :param kwargs: Expected dictionary of interface keyword arguments after parsing.
    """
    usbsio_config = UsbSioConfig.from_config_string(config, interface)
    assert usbsio_config.usb_config == usb_cfg
    assert usbsio_config.port_num == port_num
    assert usbsio_config.interface_args == args
    assert usbsio_config.interface_kwargs == kwargs


@pytest.mark.parametrize(
    "interface, config",
    [
        ("i2c", "i3c"),
        ("spi", "i2c"),
        ("i2c", "i2c,0,15,1000,cpol=1,cpha=1,nirq_port=1,7"),
        ("i2c", "i2c=1,0,15,1000"),
    ],
)
def test_libusbsio_parse_invalid_configuration_string(interface: str, config: str) -> None:
    """Test that UsbSioConfig.from_config_string raises SPSDKError for invalid configuration strings.

    This test verifies that the from_config_string method properly validates input
    and raises appropriate exceptions when given malformed or invalid configuration data.

    :param interface: The interface type to use for configuration parsing.
    :param config: Invalid configuration string that should trigger an exception.
    :raises SPSDKError: Expected exception when parsing invalid configuration.
    """
    with pytest.raises(SPSDKError):
        UsbSioConfig.from_config_string(config, interface)


def _make_i2c_device() -> UsbSioI2CDevice:
    """Create an UsbSioI2CDevice with mocked internals for unit testing.

    :return: Configured UsbSioI2CDevice with mocked port.
    """
    device = UsbSioI2CDevice.__new__(UsbSioI2CDevice)
    device._timeout = 5000
    device.i2c_address = 0x10
    device.port = MagicMock()
    return device


def _make_spi_device() -> UsbSioSPIDevice:
    """Create an UsbSioSPIDevice with mocked internals for unit testing.

    :return: Configured UsbSioSPIDevice with mocked port.
    """
    device = UsbSioSPIDevice.__new__(UsbSioSPIDevice)
    device._timeout = 5000
    device.spi_sselport = 0
    device.spi_sselpin = 15
    device.port = MagicMock()
    return device


@pytest.mark.parametrize("result,data", [(-1, None), (-1, b""), (0, b"")])
def test_usbsio_i2c_read_nak_returns_empty_bytes(result: int, data: bytes | None) -> None:
    """Test that UsbSioI2CDevice.read returns empty bytes when device NAKs.

    When libusbsio DeviceRead returns a negative result or empty data (device NAK),
    read() must return b'' so that the _wait_for_data polling loop can retry
    within the global timeout rather than raising immediately.

    :param result: libusbsio result code to simulate.
    :param data: Data returned by libusbsio to simulate.
    """
    device = _make_i2c_device()
    device.port.DeviceRead.return_value = (data, result)
    assert device.read(1) == b""


def test_usbsio_i2c_read_success_returns_data() -> None:
    """Test that UsbSioI2CDevice.read returns data on successful reads.

    When libusbsio DeviceRead returns a non-negative result and non-empty data,
    read() must return that data unchanged.
    """
    device = _make_i2c_device()
    device.port.DeviceRead.return_value = (b"\x5a", 1)
    assert device.read(1) == b"\x5a"


def test_usbsio_i2c_read_exception_raises_connection_error() -> None:
    """Test that UsbSioI2CDevice.read raises SPSDKConnectionError on libusbsio exception.

    Communication errors from libusbsio (e.g. device disconnected) must be
    converted to SPSDKConnectionError rather than propagating the raw exception.
    """
    device = _make_i2c_device()
    device.port.DeviceRead.side_effect = RuntimeError("bus error")
    with pytest.raises(SPSDKConnectionError):
        device.read(1)


@pytest.mark.parametrize("result,data", [(-1, None), (-1, b""), (0, b"")])
def test_usbsio_spi_read_nak_returns_empty_bytes(result: int, data: bytes | None) -> None:
    """Test that UsbSioSPIDevice.read returns empty bytes when device NAKs.

    When libusbsio Transfer returns a negative result or empty data (device NAK),
    read() must return b'' so that the _wait_for_data polling loop can retry
    within the global timeout rather than raising immediately.

    :param result: libusbsio result code to simulate.
    :param data: Data returned by libusbsio to simulate.
    """
    device = _make_spi_device()
    device.port.Transfer.return_value = (data, result)
    assert device.read(1) == b""


def test_usbsio_spi_read_success_returns_data() -> None:
    """Test that UsbSioSPIDevice.read returns data on successful reads.

    When libusbsio Transfer returns a non-negative result and non-empty data,
    read() must return that data unchanged.
    """
    device = _make_spi_device()
    device.port.Transfer.return_value = (b"\xa5", 1)
    assert device.read(1) == b"\xa5"


def test_usbsio_spi_read_exception_raises_connection_error() -> None:
    """Test that UsbSioSPIDevice.read raises SPSDKConnectionError on libusbsio exception.

    Communication errors from libusbsio (e.g. device disconnected) must be
    converted to SPSDKConnectionError rather than propagating the raw exception.
    """
    device = _make_spi_device()
    device.port.Transfer.side_effect = RuntimeError("bus error")
    with pytest.raises(SPSDKConnectionError):
        device.read(1)
