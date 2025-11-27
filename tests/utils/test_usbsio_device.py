#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USB-SIO device configuration testing module.

This module contains unit tests for USB-SIO device configuration parsing
functionality, ensuring proper validation of configuration strings and
error handling for invalid inputs.
"""

from typing import Any, Optional, Union

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.utils.interfaces.device.usbsio_device import UsbSioConfig


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
    usb_cfg: Optional[str],
    port_num: int,
    args: list[Union[int, str]],
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
