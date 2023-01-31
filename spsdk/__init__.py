#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
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

import logging
import logging.config
import os
import re
from typing import Any, Mapping, Optional

import colorama

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

colorama.just_fix_windows_console()


class ColoredFormatter(logging.Formatter):
    """Colored Formatter.

    SPSDK modified formatter class.
    """

    FORMAT = logging.BASIC_FORMAT
    FORMAT_DEBUG = FORMAT + " (%(relativeCreated)dms since start, %(filename)s:%(lineno)d)"

    COLORED_FORMATS = {
        logging.DEBUG: colorama.Fore.BLUE + FORMAT_DEBUG + colorama.Fore.RESET,
        logging.INFO: colorama.Fore.WHITE
        + colorama.Style.BRIGHT
        + FORMAT
        + colorama.Fore.RESET
        + colorama.Style.RESET_ALL,
        logging.WARNING: colorama.Fore.YELLOW + FORMAT_DEBUG + colorama.Fore.RESET,
        logging.ERROR: colorama.Fore.RED + FORMAT_DEBUG + colorama.Fore.RESET,
        logging.CRITICAL: colorama.Fore.RED
        + colorama.Style.BRIGHT
        + FORMAT_DEBUG
        + colorama.Fore.RESET
        + colorama.Style.RESET_ALL,
    }
    FORMATS = {
        logging.DEBUG: FORMAT_DEBUG,
        logging.INFO: FORMAT,
        logging.WARNING: FORMAT_DEBUG,
        logging.ERROR: FORMAT_DEBUG,
        logging.CRITICAL: FORMAT_DEBUG,
    }

    def __init__(
        self,
        colored: bool = True,
    ) -> None:
        """Overloaded init method to add colored parameter."""
        super().__init__()

        self.colored = colored
        self.formats = self.COLORED_FORMATS if colored else self.FORMATS

    def format(self, record: logging.LogRecord) -> str:
        """Modified format method.

        :param record: Input logging record to print.
        :return: Formatted logging string.
        """
        fmt = self.formats.get(record.levelno)
        formatter = logging.Formatter(fmt)
        if not self.colored:
            try:
                record.msg = re.sub("\\x1b\[\d{1,3}m", "", record.msg)
            except:
                # Just ignore all exceptions on this "remove color" operation
                pass
        return formatter.format(record)


spsdk_log_handler = logging.StreamHandler()
spsdk_log_handler.setFormatter(ColoredFormatter(colored=spsdk_log_handler.stream.isatty()))
spsdk_logger = logging.getLogger(__name__)
spsdk_logger.addHandler(spsdk_log_handler)
spsdk_logger.propagate = False


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
