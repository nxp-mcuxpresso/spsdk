#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""This example demonstrates how to create and Secure Boot image for LPC55xx and download it to the target."""

import os

from binascii import unhexlify

from spsdk.mboot import McuBoot, McuBootCommandError, StatusCode, scan_usb
from spsdk.sbfile.images import BootImageV20, BootSectionV2
from spsdk.sbfile.commands import CmdErase, CmdLoad, CmdReset

# Uncomment for printing debug messages
# import logging
# logging.basicConfig(level=logging.DEBUG)


DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


def build_sb(app: str, kek: bytes, address: int = 0) -> bytes:
    """Build a Secure Boot image.

    :param app: The application data
    :param kek: Key Encryption Key value
    :param address: Entry address for application
    :return: Serialized SB2.0 image
    """
    with open(app, 'rb') as f:
        boot_data = f.read()

    boot_section = BootSectionV2(
        0,
        CmdErase(address, len(boot_data)),
        CmdLoad(address, boot_data),
        CmdReset(),
        hmac_count=10)

    boot_image = BootImageV20(signed=False, kek=kek)
    boot_image.add_boot_section(boot_section)

    print(boot_image.info())

    return boot_image.export()


def main() -> None:
    """Main function."""
    # Input values
    kek_value = unhexlify('AC701E99BD3492E419B756EADC0985B3D3D0BC0FDB6B057AA88252204C2DA732')
    app_path = f'{DATA_DIR}/blinky.bin'

    # Device name ('KL27Z', 'LPC55', ...), VID:PID ('0x15A2:0x0073') or None (any from known devices)
    devices = scan_usb('LPC55')

    for device in devices:
        with McuBoot(device, True) as mb:
            mb.flash_erase_all()
            try:
                mb.receive_sb_file(build_sb(app_path, kek_value))
            except McuBootCommandError as e:
                if e.error_value != StatusCode.ROMLDR_UNEXPECTED_COMMAND:
                    raise
            mb.reset(reopen=False)


if __name__ == '__main__':
    main()
