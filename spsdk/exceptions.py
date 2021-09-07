#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Base for SPSDK exceptions."""

#######################################################################
# # Secure Provisioning SDK Exceptions
#######################################################################


class SPSDKError(Exception):
    """Secure Provisioning SDK Base Exception."""

    fmt = "SPSDK: {description}"

    def __init__(self, desc: str = None) -> None:
        """Initialize the base SPSDK Exception."""
        super().__init__()
        self.description = "Unknown Error" if desc is None else desc

    def __str__(self) -> str:
        return self.fmt.format(description=self.description)


class SPSDKValueError(SPSDKError, ValueError):
    """SPSDK standard value error."""


class SPSDKTypeError(SPSDKError, TypeError):
    """SPSDK standard type error."""


class SPSDKIOError(SPSDKError, IOError):
    """SPSDK standard IO error."""
