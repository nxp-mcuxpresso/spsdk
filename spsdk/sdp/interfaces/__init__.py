#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Connection options for SDP."""
from typing import Union

from spsdk.sdp.interfaces.uart import SdpUARTInterface
from spsdk.sdp.interfaces.usb import SdpUSBInterface

SDPDeviceTypes = Union[
    SdpUARTInterface,
    SdpUSBInterface,
]
