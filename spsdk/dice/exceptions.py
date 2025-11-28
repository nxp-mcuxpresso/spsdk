#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DICE module exception classes.

This module defines custom exception classes for DICE (Device Identifier Composition Engine)
operations, providing specific error handling for DICE verification and general DICE-related
operations within the SPSDK framework.
"""

from spsdk.exceptions import SPSDKError


class SPSDKDICEError(SPSDKError):
    """SPSDK DICE Error Exception.

    Exception class for handling errors specific to DICE (Device Identifier
    Composition Engine) operations within the SPSDK framework.
    """


class SPSDKDICEVerificationError(SPSDKDICEError):
    """SPSDK DICE verification error exception.

    This exception is raised when DICE (Device Identifier Composition Engine)
    response verification fails, providing detailed status and error information
    for debugging verification issues.
    """

    def __init__(self, status: str, message: str) -> None:
        """Initialize the Verification error object.

        :param status: Status code or identifier for the verification error.
        :param message: Human-readable error message describing the verification failure.
        """
        super().__init__(message)
        self.status = status
        self.message = message
