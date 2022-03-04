#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module provides exceptions for PFR module."""
from spsdk import SPSDKError


class SPSDKUnsupportedImageType(SPSDKError):
    """The specified Image type is not supported."""
