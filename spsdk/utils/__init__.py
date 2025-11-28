#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK utilities package initialization module.

This module serves as the entry point for the SPSDK utilities package,
providing access to common utility functions, classes, and exceptions
used throughout the SPSDK library.
"""

from spsdk.utils.exceptions import (
    SPSDKRegsError,
    SPSDKRegsErrorBitfieldNotFound,
    SPSDKRegsErrorEnumNotFound,
    SPSDKRegsErrorRegisterGroupMishmash,
    SPSDKRegsErrorRegisterNotFound,
)

__all__ = [
    "SPSDKRegsError",
    "SPSDKRegsErrorBitfieldNotFound",
    "SPSDKRegsErrorEnumNotFound",
    "SPSDKRegsErrorRegisterGroupMishmash",
    "SPSDKRegsErrorRegisterNotFound",
]
