#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDP communication protocol."""
from .interfaces.uart import SdpUARTInterface
from .interfaces.usb import SdpUSBInterface
from .sdp import SDP
