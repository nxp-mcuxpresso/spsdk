#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDP communication interfaces.

This module provides interface implementations for Serial Download Protocol (SDP)
communication, including UART and USB interface options for connecting to NXP MCUs.
"""

from typing import Union

from spsdk.sdp.interfaces.uart import SdpUARTInterface
from spsdk.sdp.interfaces.usb import SdpUSBInterface

SDPDeviceTypes = Union[
    SdpUARTInterface,
    SdpUSBInterface,
]
