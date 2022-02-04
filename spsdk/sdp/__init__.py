#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDP communication protocol."""

from .commands import ResponseValue
from .error_codes import StatusCode
from .exceptions import SdpCommandError, SdpConnectionError, SdpError
from .interfaces import scan_usb
from .sdp import SDP
from .sdps import SDPS

__all__ = [
    # Methods
    "scan_usb",
    # Classes
    "SDP",
    "SDPS",
    # Enums
    "ResponseValue",
    "StatusCode",
    # Errors
    "SdpError",
    "SdpCommandError",
    "SdpConnectionError",
]
