#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot exception classes and error handling utilities.

This module defines custom exception classes for the MBoot (MCU Boot) protocol
implementation, providing structured error handling for bootloader communication,
command execution, and data transfer operations.
"""

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.mboot.error_codes import StatusCode

########################################################################################################################
# McuBoot Exceptions
########################################################################################################################


class McuBootError(SPSDKError):
    """Base exception class for MCU Boot operations.

    This exception serves as the foundation for all MCU Boot related errors
    in the SPSDK library, providing standardized error formatting and handling.

    :cvar fmt: Default error message format template.
    """

    fmt = "MBoot: {description}"


class McuBootCommandError(McuBootError):
    """McuBootCommandError exception for MBoot command failures.

    This exception is raised when an MBoot command execution is interrupted
    or fails, providing detailed error information including the command name
    and error description based on status codes.

    :cvar fmt: Format string template for error message display.
    """

    fmt = "MBoot: {cmd_name} interrupted -> {description}"

    def __init__(self, cmd: str, value: int) -> None:
        """Initialize the Command Error exception.

        :param cmd: Name of the command causing the exception.
        :param value: Response value causing the exception.
        """
        super().__init__()
        self.cmd_name = cmd
        self.error_value = value
        self.description = (
            StatusCode.get_description(value)
            if value in StatusCode.tags()
            else f"Unknown Error 0x{value:08X}"
        )

    def __str__(self) -> str:
        """Return string representation of the exception.

        Formats the exception message using the command name and description attributes.

        :return: Formatted exception message string.
        """
        return self.fmt.format(cmd_name=self.cmd_name, description=self.description)


class McuBootDataAbortError(McuBootError):
    """McuBootDataAbortError exception for data phase abortion scenarios.

    This exception is raised when the data transmission phase is aborted by the sender
    during MCU boot operations, indicating an interruption in the data transfer process.

    :cvar fmt: Default error message format for data abortion scenarios.
    """

    fmt = "Mboot: Data aborted by sender"


class McuBootConnectionError(SPSDKConnectionError, McuBootError):
    """McuBoot connection error exception.

    This exception is raised when communication issues occur during McuBoot operations,
    such as device connection failures, timeout errors, or communication protocol problems.

    :cvar fmt: Error message format template for connection-related issues.
    """

    fmt = "MBoot: Connection issue -> {description}"
