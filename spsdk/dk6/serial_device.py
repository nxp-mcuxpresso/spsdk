#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Serial Device abstract class."""
import abc


class SerialDevice(abc.ABC):
    """Base class for all serial Interface classes."""

    @property
    @abc.abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""

    @property
    def baudrate(self) -> None:
        """Set baud rate of the device."""

    def __init__(self) -> None:
        """Initialize the Interface object.

        :param reopen: Reopen the interface after reset, defaults to False
        """

    def open(self) -> None:
        """Open the interface."""

    def close(self) -> None:
        """Close the interface."""

    @abc.abstractmethod
    def read(self, length: int) -> bytes:
        """Read data from the device."""

    def write(self, data: bytes) -> None:
        """Write a packet to the device."""
