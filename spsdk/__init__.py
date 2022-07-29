#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
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

import logging.config
import os

from .__version__ import __version__ as version
from .exceptions import (
    SPSDKAlignmentError,
    SPSDKError,
    SPSDKIOError,
    SPSDKLengthError,
    SPSDKNotImplementedError,
    SPSDKOverlapError,
    SPSDKValueError,
)

__author__ = "NXP"
__contact__ = "michal.starecek@nxp.com"
__license__ = "BSD-3-Clause"
__version__ = version
__release__ = "alpha"

# The SPSDK behavior settings
SPSDK_DATA_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
SPSDK_YML_INDENT = 2

# this import has to be after SPSDK_DATA_FOLDER definition
# pylint: disable=wrong-import-position,wrong-import-order
from spsdk.utils.misc import find_file, load_configuration

try:
    logging_config_file = find_file(
        "logging.yaml", search_paths=[".", os.path.expanduser("~/.spsdk")]
    )
    config_data = load_configuration(logging_config_file)
    logging.config.dictConfig(config_data)
    print(f"Logging config loaded from {logging_config_file}")
except SPSDKError:
    # no logging config file found
    pass
