#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK exception classes and error handling utilities.

This module defines a comprehensive hierarchy of custom exception classes
used throughout the SPSDK library for consistent error handling and reporting.
"""

from typing import Optional

#######################################################################
# # Secure Provisioning SDK Exceptions
#######################################################################


class SPSDKError(Exception):
    """Secure Provisioning SDK Base Exception.

    Base exception class for all SPSDK-related errors and exceptions.
    This class serves as the foundation for all custom exceptions within the SPSDK
    library, providing consistent error formatting and handling across the entire
    SDK. All SPSDK-specific exceptions should inherit from this base class.

    :cvar fmt: Default error message format template.
    """

    fmt = "SPSDK: {description}"

    def __init__(self, desc: Optional[str] = None) -> None:
        """Initialize the base SPSDK Exception.

        :param desc: Optional description of the exception.
        """
        super().__init__()
        self.description = desc

    def __str__(self) -> str:
        """Return string representation of the exception.

        Formats the exception message using the stored format string and description.
        If no description is provided, defaults to "Unknown Error".

        :return: Formatted exception message as string.
        """
        return self.fmt.format(description=self.description or "Unknown Error")


class SPSDKKeyError(SPSDKError, KeyError):
    """SPSDK Key Error exception for missing or invalid keys.

    This exception is raised when operations fail due to missing dictionary keys,
    invalid key formats, or key-related access errors in SPSDK components.
    """


class SPSDKValueError(SPSDKError, ValueError):
    """SPSDK standard value error exception.

    This exception is raised when an invalid value is provided to SPSDK operations,
    combining SPSDK-specific error handling with standard ValueError semantics.
    """


class SPSDKTypeError(SPSDKError, TypeError):
    """SPSDK standard type error exception.

    This exception is raised when SPSDK operations encounter type-related errors,
    combining SPSDK-specific error handling with Python's standard TypeError behavior.
    """


class SPSDKIOError(SPSDKError, IOError):
    """SPSDK standard IO error exception.

    This exception is raised when SPSDK encounters input/output related errors
    such as file access issues, communication failures, or data transfer problems.
    It combines SPSDK's standard error handling with Python's IOError semantics.
    """


class SPSDKNotImplementedError(SPSDKError, NotImplementedError):
    """SPSDK standard not implemented error exception.

    This exception is raised when attempting to use functionality that has not yet
    been implemented in the SPSDK library. It combines SPSDK's standard error
    handling with Python's built-in NotImplementedError semantics.
    """


class SPSDKLengthError(SPSDKError, ValueError):
    """SPSDK length validation error for binary data operations.

    This exception is raised when input or output data does not meet the minimum
    length requirements as declared by the container or operation being performed.
    """


class SPSDKOverlapError(SPSDKError, ValueError):
    """SPSDK exception for data overlap conflicts.

    This exception is raised when operations encounter overlapping data regions
    or conflicting memory segments that cannot be resolved automatically.
    """


class SPSDKAlignmentError(SPSDKError, ValueError):
    """SPSDK exception for data alignment errors.

    This exception is raised when data does not meet required alignment
    constraints for SPSDK operations, such as memory boundaries or
    block size requirements.
    """


class SPSDKParsingError(SPSDKError):
    """SPSDK parsing error exception.

    This exception is raised when SPSDK encounters errors during binary data
    parsing operations, such as invalid data format, corrupted data structures,
    or unsupported binary formats.
    """


class SPSDKVerificationError(SPSDKError):
    """SPSDK verification error exception.

    This exception is raised when verification operations fail during SPSDK
    operations, such as signature verification, certificate validation, or
    data integrity checks.
    """


class SPSDKCorruptedException(SPSDKError):
    """SPSDK exception for data corruption errors.

    This exception is raised when SPSDK detects corrupted data during
    processing operations such as parsing, validation, or integrity checks.
    """


class SPSDKUnsupportedOperation(SPSDKError):
    """SPSDK unsupported operation exception.

    This exception is raised when an operation is requested that is not
    supported by the current SPSDK configuration, hardware, or implementation.
    """


class SPSDKSyntaxError(SyntaxError, SPSDKError):
    """SPSDK syntax error exception.

    This exception is raised when SPSDK encounters syntax-related errors in
    configuration files, command inputs, or data parsing operations.
    """


class SPSDKFileNotFoundError(FileNotFoundError, SPSDKError):
    """SPSDK file not found exception.

    Exception raised when a required file cannot be found during SPSDK operations.
    This exception combines standard FileNotFoundError behavior with SPSDK-specific
    error handling capabilities.
    """


class SPSDKAttributeError(SPSDKError, AttributeError):
    """SPSDK standard attribute error exception.

    This exception is raised when an attribute-related error occurs within SPSDK operations,
    combining SPSDK-specific error handling with Python's standard AttributeError behavior.
    """


class SPSDKConnectionError(SPSDKError, ConnectionError):
    """SPSDK Connection Error exception class.

    This exception is raised when communication or connection issues occur
    during SPSDK operations, such as device communication failures,
    network timeouts, or interface connectivity problems.
    """


class SPSDKPermissionError(SPSDKError, PermissionError):
    """SPSDK permission error exception.

    This exception is raised when SPSDK operations encounter permission-related
    issues such as insufficient file system permissions, access denied errors,
    or security restrictions that prevent the operation from completing.
    """


class SPSDKIndexError(SPSDKError, IndexError):
    """SPSDK standard index error exception.

    This exception is raised when an index-related error occurs during SPSDK operations,
    combining SPSDK-specific error handling with standard Python IndexError behavior.
    """
