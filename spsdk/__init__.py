#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Secure Provisioning SDK is unified, reliable and easy to use SW library.

It's working across NXP MCU portfolio providing strong foundation from quick customer
prototyping up to production deployment.
The library allows the user to
    - connect and communicate with a device
    - configure the device; prepare
    - download and upload data
    - providing security operations.
It is delivered in a form of python library with functionality presented as CLI or GUI utilities.
"""

import os

from .__version__ import __version__ as version
from .exceptions import SPSDKError, SPSDKIOError, SPSDKTypeError, SPSDKValueError

__author__ = "NXP"
__contact__ = "michal.starecek@nxp.com"
__license__ = "BSD-3-Clause"
__version__ = version
__release__ = "alpha"

# The SPSDK behavior settings
SPSDK_DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
SPSDK_YML_INDENT = 2
