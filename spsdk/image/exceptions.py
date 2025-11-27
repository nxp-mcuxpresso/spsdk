#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Image processing exceptions.

This module defines custom exception classes for handling errors that occur
during image processing operations, including unsupported image types,
segment handling issues, and data stream processing failures.
"""

from spsdk.exceptions import SPSDKError


class SPSDKUnsupportedImageType(SPSDKError):
    """SPSDK exception for unsupported image types.

    This exception is raised when attempting to process an image type that is not
    supported by the SPSDK image processing functionality.
    """


class SPSDKSegmentNotPresent(SPSDKError):
    """SPSDK exception for missing image segments.

    This exception is raised when a required segment is not found in an image
    during processing or validation operations.
    """


class SPSDKRawDataException(SPSDKError):
    """Exception raised when raw data operations fail.

    This exception is thrown when SPSDK encounters errors during raw data
    reading, parsing, or processing operations in image handling workflows.
    """


class SPSDKStreamReadFailed(SPSDKRawDataException):
    """SPSDK exception for stream reading failures.

    This exception is raised when the read_raw_data operation fails to read
    data from a stream due to various stream-related issues such as
    corruption, unexpected end of stream, or read access problems.
    """


class SPSDKNotEnoughBytesException(SPSDKRawDataException):
    """SPSDK exception for insufficient data during raw data reading operations.

    This exception is raised when read_raw_data operations cannot read the
    required amount of data from the source, indicating data truncation or
    unexpected end of data stream.
    """
