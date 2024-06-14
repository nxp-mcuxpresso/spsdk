#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides exceptions for SPSDK utilities."""
from spsdk.exceptions import SPSDKError


class SPSDKRegsError(SPSDKError):
    """General Error group for utilities SPSDK registers module."""


class SPSDKRegsErrorRegisterGroupMishmash(SPSDKRegsError):
    """Register Group inconsistency problem."""


class SPSDKRegsErrorRegisterNotFound(SPSDKRegsError):
    """Register has not been found."""


class SPSDKRegsErrorBitfieldNotFound(SPSDKRegsError):
    """Bitfield has not been found."""


class SPSDKRegsErrorEnumNotFound(SPSDKRegsError):
    """Enum has not been found."""


class SPSDKTimeoutError(SPSDKError, TimeoutError):
    """SPSDK Timeout."""
