#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot protocol base implementation.

This module provides the base protocol class for MBoot communication,
defining the fundamental interface and common functionality for MBoot
protocol implementations across different transport layers.
"""

from spsdk.utils.interfaces.protocol.protocol_base import ProtocolBase


class MbootProtocolBase(ProtocolBase):
    """MBoot protocol base class for secure provisioning operations.

    This class serves as the foundation for MBoot protocol implementations,
    providing common functionality and configuration for communication with
    NXP MCU devices during secure provisioning processes.

    :cvar allow_abort: Controls whether protocol operations can be aborted.
    :cvar need_data_split: Indicates if large data transfers require splitting.
    """

    allow_abort: bool = False
    need_data_split: bool = True
