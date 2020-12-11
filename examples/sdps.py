#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example demonstrates how to write memory using SDPS."""
import logging
import os

from spsdk.sdp import SDPS, scan_usb

# Uncomment for printing debug messages
logging.basicConfig(level=logging.DEBUG)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


def program_device() -> None:
    """
    Write app to MX815 device using SDPS
    """
    device_name = 'MX815'
    devices = scan_usb(device_name)
    if devices:
        with SDPS(devices[0], device_name) as sdps:
            with open(f'{DATA_DIR}/test_m815s.bin', 'rb') as f:
                data = f.read()
                sdps.write_file(data)


if __name__ == '__main__':
    program_device()
