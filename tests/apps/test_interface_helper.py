#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.apps.utils.interface_helper import load_interface_config
from spsdk.apps.utils.utils import SPSDKAppError


@pytest.mark.parametrize(
    "cli_params,interface,params,extra_params",
    [
        ({"port": "COM10"}, "uart", "COM10", None),
        (
            {
                "port": "COM10",
                "usb": None,
                "sdio": None,
                "lpcusbsio": None,
                "plugin": None,
                "buspal": None,
            },
            "uart",
            "COM10",
            None,
        ),
        (
            {
                "port": None,
                "usb": "0x1fc9:0x0025",
                "sdio": None,
                "lpcusbsio": None,
                "plugin": None,
                "buspal": None,
            },
            "usb",
            "0x1fc9:0x0025",
            None,
        ),
        (
            {
                "port": None,
                "usb": None,
                "sdio": "/sdio/path",
                "lpcusbsio": None,
                "plugin": None,
                "buspal": None,
            },
            "sdio",
            "/sdio/path",
            None,
        ),
        (
            {
                "port": None,
                "usb": None,
                "sdio": None,
                "lpcusbsio": "spi",
                "plugin": None,
                "buspal": None,
            },
            "usbsio_spi",
            "spi",
            None,
        ),
        (
            {
                "port": None,
                "usb": None,
                "sdio": None,
                "lpcusbsio": "i2c",
                "plugin": None,
                "buspal": None,
            },
            "usbsio_i2c",
            "i2c",
            None,
        ),
        (
            {
                "port": "COM10",
                "usb": None,
                "sdio": None,
                "lpcusbsio": None,
                "plugin": None,
                "buspal": "spi",
            },
            "buspal_spi",
            "COM10",
            "spi",
        ),
        (
            {
                "port": "COM10",
                "usb": None,
                "sdio": None,
                "lpcusbsio": None,
                "plugin": None,
                "buspal": "i2c",
            },
            "buspal_i2c",
            "COM10",
            "i2c",
        ),
        (
            {
                "port": None,
                "usb": None,
                "sdio": None,
                "lpcusbsio": None,
                "plugin": "identifier=plugin_name,param1=value1,param2=value2",
                "buspal": None,
            },
            "plugin_name",
            "param1=value1,param2=value2",
            None,
        ),
    ],
)
def test_load_interface_config(cli_params, interface, params, extra_params):
    iface_config = load_interface_config(cli_params)
    assert iface_config.IDENTIFIER == interface
    assert iface_config.params == params
    assert iface_config.extra_params == extra_params


@pytest.mark.parametrize(
    "cli_params",
    [
        {
            "port": None,
            "usb": None,
            "sdio": None,
            "lpcusbsio": None,
            "plugin": None,
            "buspal": None,
        },
        {
            "port": "COM13",
            "usb": "0x1fc9:0x0025",
            "sdio": None,
            "lpcusbsio": None,
            "plugin": None,
            "buspal": None,
        },
        {
            "port": None,
            "usb": None,
            "sdio": None,
            "lpcusbsio": None,
            "plugin": None,
            "buspal": "spi",
        },
    ],
)
def test_load_interface_config_no_interface(cli_params):
    with pytest.raises(SPSDKAppError):
        load_interface_config(cli_params)
