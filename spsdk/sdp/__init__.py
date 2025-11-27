#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDP (Serial Download Protocol) communication module.

This module provides a unified interface for SDP communication across different
transport layers including UART and USB interfaces. It enables secure provisioning
and device communication for NXP MCUs supporting the SDP protocol.
"""

from spsdk.sdp.interfaces.uart import SdpUARTInterface as SdpUARTInterface
from spsdk.sdp.interfaces.usb import SdpUSBInterface as SdpUSBInterface
from spsdk.sdp.sdp import SDP as SDP
