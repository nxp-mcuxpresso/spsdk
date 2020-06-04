#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDP communication protocol."""

from .sdp import SDP
from .interfaces import scan_usb
from .exceptions import SdpError, SdpCommandError, SdpConnectionError
from .error_codes import StatusCode
from .commands import ResponseValue

from .hab_logs import parse_mx6_log, parse_mx7_log, parse_mxrt_log

__all__ = [
    # Methods
    'scan_usb',
    'parse_mx6_log',
    'parse_mx7_log',
    'parse_mxrt_log',
    # Classes
    'SDP',
    # Enums
    'ResponseValue',
    'StatusCode',
    # Errors
    'SdpError',
    'SdpCommandError',
    'SdpConnectionError',
]
