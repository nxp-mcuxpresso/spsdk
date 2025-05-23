#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides exceptions for PFR module."""
from spsdk.exceptions import SPSDKError


class SPSDKUnsupportedImageType(SPSDKError):
    """The specified Image type is not supported."""


class SPSDKSegmentNotPresent(SPSDKError):
    """The segment is missing in the image."""


class SPSDKRawDataException(SPSDKError):
    """Raw data read failed."""


class SPSDKStreamReadFailed(SPSDKRawDataException):
    """Read_raw_data could not read stream."""


class SPSDKNotEnoughBytesException(SPSDKRawDataException):
    """Read_raw_data could not read enough data."""
