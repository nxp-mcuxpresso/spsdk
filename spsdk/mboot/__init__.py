#!/usr/bin/env python
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MCU Bootloader communication module.

This module provides unified interface and communication protocols for interacting
with NXP MCU bootloaders across different transport layers including UART, CAN,
I2C, SPI, and SDIO interfaces.
"""

from spsdk.mboot.interfaces.buspal import MbootBuspalI2CInterface, MbootBuspalSPIInterface
from spsdk.mboot.interfaces.can_interface import MbootCANInterface
from spsdk.mboot.interfaces.sdio import MbootSdioInterface
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.interfaces.usbsio import MbootUsbSioI2CInterface, MbootUsbSioSPIInterface
from spsdk.mboot.mcuboot import McuBoot as McuBoot

MbootDeviceTypes = (
    MbootBuspalI2CInterface
    | MbootBuspalSPIInterface
    | MbootSdioInterface
    | MbootUARTInterface
    | MbootUSBInterface
    | MbootUsbSioI2CInterface
    | MbootUsbSioSPIInterface
    | MbootCANInterface
)
