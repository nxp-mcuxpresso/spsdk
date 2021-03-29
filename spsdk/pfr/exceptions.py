#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides exceptions for PFR module."""
from spsdk import SPSDKError

class SPSDKPfrError(SPSDKError):
    """General PFR error."""

class SPSDKPfrConfigError(SPSDKPfrError):
    """General PFR configuration error."""

class SPSDKPfrConfigReadError(SPSDKPfrConfigError):
    """Configuration file decode error."""

class SPSDKPfrRotkhIsNotPresent(SPSDKPfrError):
    """The configuration area doesn't provide ROTKH field."""
