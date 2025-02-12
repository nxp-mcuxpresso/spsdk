#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module containing various functions/modules used throughout the SPSDK."""

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
