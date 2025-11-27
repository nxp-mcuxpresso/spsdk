#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 serial device abstract interface.

This module provides the abstract base class for serial device communication
in the DK6 context, defining the interface that concrete serial device
implementations must follow.
"""

import abc


class SerialDevice(abc.ABC):
    """Abstract base class for serial communication interfaces in SPSDK.

    This class defines the common interface for all serial device implementations,
    providing standardized methods for opening, closing, reading, and writing data
    to serial devices across the NXP MCU portfolio.
    """

    @property
    @abc.abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether the serial interface is open.

        :return: True if interface is open, False otherwise.
        """

    @property
    def baudrate(self) -> None:
        """Set baud rate of the device.

        :raises SPSDKError: If baud rate configuration fails.
        """

    def __init__(self) -> None:
        """Initialize the Interface object.

        This constructor sets up a new Interface instance with default configuration.
        """

    def open(self) -> None:
        """Open the serial device interface.

        Establishes a connection to the serial device, making it ready for communication.

        :raises SPSDKError: If the device cannot be opened or is already in use.
        :raises SPSDKConnectionError: If connection to the serial device fails.
        """

    def close(self) -> None:
        """Close the interface.

        Closes the serial device connection and releases any associated resources.
        """

    @abc.abstractmethod
    def read(self, length: int) -> bytes:
        """Read data from the device.

        :param length: Number of bytes to read from the device.
        :return: Data read from the device as bytes.
        """

    def write(self, data: bytes) -> None:
        """Write a packet to the device.

        :param data: The byte data to be written to the device.
        """
