#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides exceptions for TP module."""
from spsdk.exceptions import SPSDKError


class SPSDKTpError(SPSDKError):
    """General TP error."""


class SPSDKTpConfigError(SPSDKTpError):
    """General TP configuration error."""


class SPSDKTpTimeoutError(SPSDKTpError):
    """TP operation has overflow timeout."""


class SPSDKTpTargetError(SPSDKTpError):
    """TP target failed."""
