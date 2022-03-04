#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Connection options for SDP."""

from .base import Interface, SDPInterface
from .uart import Uart, scan_uart
from .usb import (  # type: ignore  # ignore problems due to OS specific implementation
    RawHid,
    scan_usb,
)
