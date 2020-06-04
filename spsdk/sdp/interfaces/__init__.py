#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Connection options for SDP."""

from .base import Interface
from .usb import scan_usb, RawHid  # type: ignore  # ignore problems due to OS specific implementation
from .uart import scan_uart, Uart
