#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Base for SPSDK exceptions."""

#######################################################################
# # Boot SDK Exceptions
#######################################################################
class SPSDKError(Exception):
    """Boot SDK Base Exception."""

    fmt = 'SPSDK: {description}'

    def __init__(self, desc: str = None) -> None:
        """Initialize the base SPSDK Exception."""
        super().__init__()
        self.description = "Unknown Error" if desc is None else desc

    def __str__(self) -> str:
        return self.fmt.format(description=self.description)
