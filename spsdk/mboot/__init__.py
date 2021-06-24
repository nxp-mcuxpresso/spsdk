#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing communication with the MCU Bootloader."""

from .mcuboot import McuBoot
from .commands import CommandTag, KeyProvUserKeyType, GenerateKeyBlobSelect
from .memories import ExtMemPropTags, ExtMemId
from .properties import PropertyTag, PeripheryTag, Version, parse_property_value
from .interfaces import scan_usb
from .exceptions import (
    McuBootError,
    McuBootCommandError,
    McuBootConnectionError,
    McuBootDataAbortError,
)
from .error_codes import StatusCode

__all__ = [
    # global methods
    "scan_usb",
    "parse_property_value",
    # classes
    "McuBoot",
    "Version",
    # enums
    "PropertyTag",
    "PeripheryTag",
    "CommandTag",
    "StatusCode",
    "ExtMemId",
    "KeyProvUserKeyType",
    # exceptions
    "McuBootError",
    "McuBootCommandError",
    "McuBootConnectionError",
]
