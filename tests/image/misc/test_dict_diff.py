#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of dictionary compare."""

from spsdk.image.misc import dict_diff


def test_simple_diff():
    """Simple test of dictionary compare with integers."""
    main = {"a": "0b00", "b": "0b01"}
    mod = {"b": "0b11"}

    assert dict_diff(main, mod) == {"b": "0b11"}


def test_simple_diff_strings():
    """Simple test of dictionary compare with integers."""
    main = {"a": "0b00", "b": "Hello", "c": "Good Morning"}
    mod = {"b": "Cao", "c": "Good Morning"}

    assert dict_diff(main, mod) == {"b": "Cao"}


def test_nested_diff():
    """Simple test of dictionary compare with nested dictionaries."""
    main = {
        "BOOT_CFG": {"DEFAULT_ISP_MODE": "0b000", "BOOT_SPEED": "0b00", "BOOT_FAILURE_PIN": "0x0"},
        "SPI_FLASH_CFG": "0b0_0000",
        "USB_ID": {"USB_VENDOR_ID": "0x00", "USB_PRODUCT_ID": "0x00"},
        "CUSTOMER_DEFINED0": "0x0000",
        "CUSTOMER_DEFINED1": "0x0000",
        "CUSTOMER_DEFINED2": "0x0000",
        "CUSTOMER_DEFINED3": "0x0000",
    }
    mod = {
        "BOOT_CFG": {"DEFAULT_ISP_MODE": "0b000", "BOOT_SPEED": "0b11", "BOOT_FAILURE_PIN": "0x0"},
        "CUSTOMER_DEFINED0": "0x0000",
        "CUSTOMER_DEFINED1": "0x0000",
        "CUSTOMER_DEFINED2": "0xABCD",
        "CUSTOMER_DEFINED3": "0xEF01",
        "ThisOneDoesn'tExists": "0x00",
    }

    expect = {
        "BOOT_CFG": {"BOOT_SPEED": "0b11"},
        "CUSTOMER_DEFINED2": "0xABCD",
        "CUSTOMER_DEFINED3": "0xEF01",
    }

    assert expect == dict_diff(main, mod)
