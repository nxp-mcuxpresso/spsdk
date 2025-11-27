#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK dictionary comparison utilities.

This module contains unit tests for the dict_diff functionality from
spsdk.image.misc module, which provides dictionary comparison and
difference detection capabilities.
"""

from spsdk.image.misc import dict_diff


def test_simple_diff() -> None:
    """Test dictionary difference functionality with simple integer values.

    Verifies that dict_diff correctly identifies and returns differences
    between a main dictionary and a modification dictionary, specifically
    testing with binary string representations.
    """
    main = {"a": "0b00", "b": "0b01"}
    mod = {"b": "0b11"}

    assert dict_diff(main, mod) == {"b": "0b11"}


def test_simple_diff_strings() -> None:
    """Test dictionary comparison functionality with string values.

    Verifies that dict_diff correctly identifies differences between two dictionaries
    containing string values, returning only the key-value pairs that differ.

    :param: No parameters - this is a test function.
    :raises AssertionError: If the dictionary comparison does not produce expected results.
    """
    main = {"a": "0b00", "b": "Hello", "c": "Good Morning"}
    mod = {"b": "Cao", "c": "Good Morning"}

    assert dict_diff(main, mod) == {"b": "Cao"}


def test_nested_diff() -> None:
    """Test dictionary comparison functionality with nested dictionary structures.

    This test verifies that the dict_diff function correctly identifies differences
    between two dictionaries containing nested dictionary values. It tests scenarios
    including modified nested values, changed top-level values, missing keys, and
    added keys that don't exist in the original dictionary.
    """
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
