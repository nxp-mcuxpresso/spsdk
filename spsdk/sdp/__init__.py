#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDP communication protocol."""

from .sdp import SDP
from .sdps import SDPS
from .interfaces import scan_usb
from .exceptions import SdpError, SdpCommandError, SdpConnectionError
from .error_codes import StatusCode
from .commands import ResponseValue


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
