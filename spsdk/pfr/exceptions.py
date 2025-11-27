#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR (Protected Flash Region) exception classes.

This module defines custom exception classes for handling errors specific
to PFR operations, including configuration errors, validation failures,
and missing component errors.
"""

from spsdk.exceptions import SPSDKError


class SPSDKPfrError(SPSDKError):
    """General PFR error exception class.

    This exception is raised when PFR (Protected Flash Region) operations
    encounter errors during processing, validation, or manipulation of PFR data.
    """


class SPSDKPfrConfigError(SPSDKPfrError):
    """PFR configuration error exception.

    This exception is raised when there are issues with PFR (Protected Flash Region)
    configuration data, such as invalid parameters, malformed configuration files,
    or configuration validation failures.
    """


class SPSDKPfrConfigReadError(SPSDKPfrConfigError):
    """SPSDK PFR configuration file read error exception.

    This exception is raised when there are issues reading or decoding PFR
    configuration files, such as invalid file format, corrupted data, or
    unsupported configuration structure.
    """


class SPSDKPfrRotkhIsNotPresent(SPSDKPfrError):
    """SPSDK PFR ROTKH missing exception.

    Exception raised when the Protected Flash Region configuration area
    does not contain the required Root of Trust Key Hash (ROTKH) field.
    """


class SPSDKPfrcMissingConfigError(SPSDKPfrError):
    """SPSDK PFR configuration missing error exception.

    This exception is raised when required configuration data is missing
    during PFR (Protected Flash Region) operations, preventing proper
    translation or processing of configuration conditions.
    """
