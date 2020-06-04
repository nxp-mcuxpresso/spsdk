#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows how to read properties of the target's bootloader."""

from typing import Optional

from spsdk.mboot import McuBoot, scan_usb

# Uncomment for printing debug messages
# import logging
# logging.basicConfig(level=logging.DEBUG)


def mboot_properties(name: str = None) -> Optional[list]:
    """Get McuBoot properties.

    :param name: Device name ('KL27Z', 'LPC55', ...), VID:PID ('0x15A2:0x0073') or None (any from known devices)
    :return: Interface object
    """
    props = None
    devices = scan_usb(name)
    if devices:
        with McuBoot(devices[0]) as mb:
            props = mb.get_property_list()
    return props


def main() -> None:
    """Main function."""
    property_list = mboot_properties()
    assert property_list, "Error reading properties!"
    for prop in property_list:
        print(prop)


if __name__ == '__main__':
    main()
