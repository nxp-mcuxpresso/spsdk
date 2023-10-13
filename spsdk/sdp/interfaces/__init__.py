#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Connection options for SDP."""
from typing import Union

from .uart import SdpUARTInterface
from .usb import SdpUSBInterface

SDPDeviceTypes = Union[
    SdpUARTInterface,
    SdpUSBInterface,
]
