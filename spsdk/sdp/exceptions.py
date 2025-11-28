#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP (Serial Download Protocol) exception classes.

This module defines custom exception classes for handling errors that occur
during SDP operations, including command execution errors and connection issues.
"""

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.sdp.error_codes import StatusCode


########################################################################################################################
# Serial Downloader Protocol (SDP) Exceptions
########################################################################################################################
class SdpError(SPSDKError):
    """Base exception class for SDP (Serial Download Protocol) operations.

    This exception serves as the foundation for all SDP-related errors in SPSDK,
    providing consistent error formatting and handling across SDP functionality.

    :cvar fmt: Format string template for SDP error messages.
    """

    fmt = "SDP: {description}"


class SdpCommandError(SdpError):
    """SDP command execution exception.

    This exception is raised when an SDP command fails during execution,
    providing detailed error information including the command name and
    status code description.

    :cvar fmt: Format string template for error message display.
    """

    fmt = "SDP: {cmd_name} interrupted -> {description}"

    def __init__(self, cmd: str, value: int):
        """Initialize the SDP command exception.

        Creates an exception instance for SDP command errors with error code resolution.

        :param cmd: Name of the SDP command that caused the exception.
        :param value: Response error value from the SDP command.
        """
        super().__init__()
        self.cmd_name = cmd
        self.error_value = value
        self.description = (
            StatusCode.from_tag(value).description
            if value in StatusCode.tags()
            else f"Unknown Error 0x{value:08X}"
        )

    def __str__(self) -> str:
        """Return string representation of the exception.

        Formats the exception message using the command name and description attributes.

        :return: Formatted exception message string.
        """
        return self.fmt.format(cmd_name=self.cmd_name, description=self.description)


class SdpConnectionError(SPSDKConnectionError, SdpError):
    """SDP connection error exception.

    This exception is raised when connection-related issues occur during
    SDP (Serial Download Protocol) operations, such as communication
    failures or device connectivity problems.

    :cvar fmt: Error message format template for connection issues.
    """

    fmt = "SDP: Connection issue -> {description}"
