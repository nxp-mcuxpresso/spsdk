#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK device interface base class.

This module provides the abstract base class for all device communication
interfaces in SPSDK, defining the common contract for device operations.
"""

import logging
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Optional, Type

from typing_extensions import Self

logger = logging.getLogger(__name__)


class DeviceBase(ABC):
    """Abstract base class for device communication interfaces.

    This class defines the standard interface for all device communication
    implementations in SPSDK, providing context manager support and abstract
    methods for device operations like opening, closing, reading, and writing data.
    """

    def __enter__(self) -> Self:
        """Enter the runtime context of the device interface.

        This method is used as part of the context manager protocol to automatically
        handle device resource management. It opens the device connection and returns
        the device instance for use within the 'with' statement block.

        :return: The device instance itself for use in context manager.
        """
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Clean up device resources and close the connection.

        This method is called automatically when exiting a context manager block.
        It ensures proper cleanup of the device interface by closing any open connections.

        :param exception_type: Type of exception that caused the context to exit, if any.
        :param exception_value: Exception instance that caused the context to exit, if any.
        :param traceback: Traceback object associated with the exception, if any.
        """
        self.close()

    @property
    @abstractmethod
    def is_opened(self) -> bool:
        """Indicates whether interface is open.

        :return: True if interface is open, False otherwise.
        """

    @abstractmethod
    def open(self) -> None:
        """Open the interface.

        Establishes connection to the device interface, making it ready for communication.

        :raises SPSDKError: If the interface cannot be opened or is already open.
        """

    @abstractmethod
    def close(self) -> None:
        """Close the interface.

        Properly closes the communication interface and releases any associated resources.
        """

    @abstractmethod
    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the device.

        :param length: Length of data to be read in bytes.
        :param timeout: Read timeout in milliseconds, None for default timeout.
        :return: Data read from the device.
        """

    @abstractmethod
    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to the device.

        :param data: Data to be written to the device.
        :param timeout: Write timeout to be applied in milliseconds.
        """

    @property
    @abstractmethod
    def timeout(self) -> int:
        """Get the timeout value for device communication.

        :return: Timeout value in milliseconds.
        """

    @timeout.setter
    @abstractmethod
    def timeout(self, value: int) -> None:
        """Set timeout value for device communication.

        :param value: Timeout value in milliseconds.
        """

    @abstractmethod
    def __str__(self) -> str:
        """Return string containing information about the interface.

        :return: String representation of the interface with relevant details.
        """
