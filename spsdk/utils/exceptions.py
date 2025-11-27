#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK utilities exception classes and error handling.

This module defines specialized exception classes for SPSDK utilities,
extending the base SPSDKError for specific error scenarios in registers,
bitfields, enums, and timeout operations.
"""

from spsdk.exceptions import SPSDKError


class SPSDKRegsError(SPSDKError):
    """SPSDK Registers Error Exception.

    This exception class represents errors that occur during SPSDK register
    operations including register parsing, validation, and manipulation tasks.
    """


class SPSDKRegsErrorRegisterGroupMishmash(SPSDKRegsError):
    """SPSDK Register Group Mishmash Exception.

    This exception is raised when there are inconsistencies or conflicts
    within register group configurations, such as overlapping registers,
    invalid group definitions, or mismatched register properties within
    the same group.
    """


class SPSDKRegsErrorRegisterNotFound(SPSDKRegsError):
    """SPSDK register lookup exception for missing registers.

    This exception is raised when attempting to access or manipulate a register
    that cannot be found in the current register database or configuration.
    """


class SPSDKRegsErrorBitfieldNotFound(SPSDKRegsError):
    """SPSDK registers exception for missing bitfield operations.

    This exception is raised when attempting to access or manipulate a bitfield
    that does not exist in the register definition or configuration.
    """


class SPSDKRegsErrorEnumNotFound(SPSDKRegsError):
    """SPSDK registers exception for missing enumeration definitions.

    This exception is raised when attempting to access or reference an enumeration
    that cannot be found in the registers configuration or definition files.
    """


class SPSDKTimeoutError(SPSDKError, TimeoutError):
    """SPSDK timeout exception for operations that exceed time limits.

    This exception is raised when SPSDK operations fail to complete within
    the specified timeout period, combining standard timeout behavior with
    SPSDK-specific error handling.
    """
