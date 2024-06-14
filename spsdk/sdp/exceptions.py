#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Exceptions used in the SDP module."""

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.sdp.error_codes import StatusCode


########################################################################################################################
# Serial Downloader Protocol (SDP) Exceptions
########################################################################################################################
class SdpError(SPSDKError):
    """SDP Module: Base Exception."""

    fmt = "SDP: {description}"


class SdpCommandError(SdpError):
    """SDP Module: Command Exception."""

    fmt = "SDP: {cmd_name} interrupted -> {description}"

    def __init__(self, cmd: str, value: int):
        """Initialize the Exception object.

        :param cmd: Name of the command causing the exception
        :param value: Response value causing the exception
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
        return self.fmt.format(cmd_name=self.cmd_name, description=self.description)


class SdpConnectionError(SPSDKConnectionError, SdpError):
    """SDP Module: Connection Exception."""

    fmt = "SDP: Connection issue -> {description}"
