#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows how to read properties of the target's bootloader."""

from typing import Optional

from spsdk.exceptions import SPSDKError
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.mcuboot import McuBoot

# Uncomment for printing debug messages
# import logging
# logging.basicConfig(level=logging.DEBUG)


def mboot_properties(name: Optional[str] = None) -> Optional[list]:
    """Get McuBoot properties.

    :param name: Device name ('KL27Z', 'LPC55', ...), VID:PID ('0x15A2:0x0073') or None (any from known devices)
    :return: Interface object
    """
    props = None
    interfaces = MbootUSBInterface.scan(device_id=name)
    if interfaces:
        with McuBoot(interfaces[0]) as mb:
            props = mb.get_property_list()
    return props


def main() -> None:
    """Main function.

    :raises SPSDKError: When reading properties ends with error
    """
    property_list = mboot_properties()
    if not property_list:
        raise SPSDKError("Error reading properties!")
    for prop in property_list:
        print(prop)


if __name__ == "__main__":
    main()
