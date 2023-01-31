#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example demonstrates how to read memory using SDP."""

from typing import Optional

from spsdk.sdp import SDP, scan_usb

# Uncomment for printing debug messages
# import logging
# logging.basicConfig(level=logging.DEBUG)


def read_memory(address: int, length: int, device_name: Optional[str] = None) -> Optional[bytes]:
    """Read memory using USB interface.

    To see all available device names (and their respective VID:PID):
      spsdk/sdp/interfaces/usb.py -> USB_DEVICES
    If device_name is not specified, function will use first available SDP device.

    :param address: The address in target memory
    :param length: Count of bytes to read
    :param device_name: i.MX-RT device name or VID:PID
    :return: bytes or None
    """
    devices = scan_usb(device_name)
    if devices:
        with SDP(devices[0]) as sdp:
            return sdp.read(address, length, 8)
    return None


if __name__ == "__main__":
    DATA = read_memory(0, 100)
    print(DATA)
