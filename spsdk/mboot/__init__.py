#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing communication with the MCU Bootloader."""

from typing import Union

from spsdk.mboot.interfaces.buspal import MbootBuspalI2CInterface, MbootBuspalSPIInterface
from spsdk.mboot.interfaces.can_interface import MbootCANInterface
from spsdk.mboot.interfaces.sdio import MbootSdioInterface
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.interfaces.usbsio import MbootUsbSioI2CInterface, MbootUsbSioSPIInterface
from spsdk.mboot.mcuboot import McuBoot as McuBoot

MbootDeviceTypes = Union[
    MbootBuspalI2CInterface,
    MbootBuspalSPIInterface,
    MbootSdioInterface,
    MbootUARTInterface,
    MbootUSBInterface,
    MbootUsbSioI2CInterface,
    MbootUsbSioSPIInterface,
    MbootCANInterface,
]
