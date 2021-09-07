#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing communication with the MCU Bootloader."""

from .commands import CommandTag, GenerateKeyBlobSelect, KeyProvUserKeyType
from .error_codes import StatusCode
from .exceptions import (
    McuBootCommandError,
    McuBootConnectionError,
    McuBootDataAbortError,
    McuBootError,
)
from .interfaces import scan_usb
from .mcuboot import McuBoot
from .memories import ExtMemId, ExtMemPropTags, MemId
from .properties import PeripheryTag, PropertyTag, Version, parse_property_value

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
