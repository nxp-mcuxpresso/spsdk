#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP protocol base."""
from spsdk.utils.interfaces.protocol.protocol_base import ProtocolBase


class SDPProtocolBase(ProtocolBase):
    """SDP protocol base class."""

    expect_status = True

    def configure(self, config: dict) -> None:
        """Configure device.

        :param config: parameters dictionary
        """
