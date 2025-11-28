#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK generic command interface definitions.

This module provides abstract base classes for implementing command packets
and responses across different communication interfaces in SPSDK.
"""

from abc import ABC, abstractmethod


class CmdResponseBase(ABC):
    """Abstract base class for command response objects.

    This class defines the interface for all command response implementations,
    providing a standardized way to handle and represent command execution results
    across different communication protocols and devices.
    """

    @abstractmethod
    def __str__(self) -> str:
        """Get string representation of the object.

        :return: String representation containing object information.
        """

    @property
    @abstractmethod
    def value(self) -> int:
        """Return an integer representation of the response.

        :return: Integer value of the response.
        """


class CmdPacketBase(ABC):
    """Abstract base class for command protocol packets.

    This class defines the interface for command packets used in communication
    protocols, providing a foundation for implementing specific packet formats
    and serialization methods.
    """

    @abstractmethod
    def export(self, padding: bool = True) -> bytes:
        """Export CmdPacket into bytes.

        :param padding: If True, add padding to specific size.
        :return: Exported object into bytes.
        """
