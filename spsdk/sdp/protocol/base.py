#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP protocol base implementation.

This module provides the base class for Serial Download Protocol (SDP) implementations
in SPSDK, defining the common interface and functionality for SDP communication.
"""

from spsdk.utils.interfaces.protocol.protocol_base import ProtocolBase


class SDPProtocolBase(ProtocolBase):
    """SDP protocol base class.

    This class provides the foundation for Serial Download Protocol (SDP) implementations,
    offering common functionality and interface for SDP communication with NXP devices.

    :cvar expect_status: Flag indicating whether status response is expected from device.
    """

    expect_status = True

    def configure(self, config: dict) -> None:
        """Configure device with provided parameters.

        :param config: Dictionary containing configuration parameters for the device.
        :raises SPSDKError: If configuration fails or invalid parameters are provided.
        """
