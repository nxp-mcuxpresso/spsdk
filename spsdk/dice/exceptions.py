#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Exceptions used throughout DICE module."""

from spsdk.exceptions import SPSDKError


class SPSDKDICEError(SPSDKError):
    """General DICE error."""


class SPSDKDICEVerificationError(SPSDKDICEError):
    """Error during DICE response verification."""

    def __init__(self, status: str, message: str) -> None:
        """Initialize the Verification error object."""
        super().__init__(message)
        self.status = status
        self.message = message
