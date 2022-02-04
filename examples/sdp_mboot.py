#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example shows how to download a flashloader into i.MX RT10xx device and read bootloader properties."""

import os
import sys
from time import sleep

from spsdk import mboot, sdp

# Uncomment for printing debug messages
# import logging
# logging.basicConfig(level=logging.DEBUG)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def run_flash_loader(
    load_address: int, start_address: int, data: bytes, device_name: str = None
) -> bool:
    """Load an execute flashloader binary in i.MX-RT.

    :param load_address: Destination address in target memory
    :param start_address: Execution address
    :param data: flashloader binary data
    :param device_name: i.MX-RT device name or VID:PID
    :return: True if running flashloader was successfull
    :raise sdp.SdpError: If SDP operation fails
    """
    devices = sdp.scan_usb(device_name)
    if not devices:
        return False

    try:
        with sdp.SDP(devices[0], True) as serial_downloader:
            serial_downloader.write_file(load_address, data)
            serial_downloader.jump_and_run(start_address)
            return True
    except sdp.SdpError:
        return False


def main() -> None:
    """Main function."""
    with open(f"{DATA_DIR}/ivt_flashloader.bin", "rb") as f:
        flash_loader_data = f.read()

    if run_flash_loader(0x20000000, 0x20000400, flash_loader_data):
        sleep(6)  # wait for device startup
        print("flash-loader executed")

    # Scan for MCU-BOOT device
    devices = mboot.scan_usb()
    if not devices:
        print("Not founded MCU-BOOT device")
        sys.exit()

    try:
        with mboot.McuBoot(devices[0], True) as mb:
            mb.reopen = False
            # data = mb.read_memory(0, 500)
            property_list = mb.get_property_list()
            mb.reset()

    except mboot.McuBootError as e:
        print(str(e))
        sys.exit()

    for prop in property_list:
        print(prop)


if __name__ == "__main__":
    main()
