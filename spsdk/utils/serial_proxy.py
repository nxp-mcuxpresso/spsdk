#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Serial communication proxy utilities.

This module provides proxy classes that serve as replacements for the standard
serial.Serial class, enabling enhanced serial communication handling with
additional functionality for SPSDK applications.
"""

import logging

# pylint: disable=unused-import  # Type is necessary for Mypy
from typing import Optional, Type

logger = logging.getLogger(__name__)


class SerialProxy:
    """Serial communication proxy for testing and simulation.

    This class provides a mock implementation of serial.Serial that can be used
    for testing serial communication without actual hardware. It uses pre-recorded
    request-response pairs to simulate device communication patterns.

    :cvar responses: Dictionary mapping write data to corresponding read responses.
    :cvar ignore_ack: Flag to control ACK packet handling in internal buffer.
    """

    responses: dict[bytes, bytes] = {}
    ignore_ack: bool = False

    @classmethod
    def init_proxy(cls, data: dict[bytes, bytes], ignore_ack: bool = False) -> "Type[SerialProxy]":
        """Initialize response dictionary of write and read bytes.

        Configures the SerialProxy class with predefined responses for write operations
        and sets ACK packet handling behavior.

        :param data: Dictionary mapping write bytes to corresponding read response bytes.
        :param ignore_ack: Don't modify internal buffer upon receiving an ACK packet.
        :return: SerialProxy class with configured response data.
        """
        cls.responses = data
        cls.ignore_ack = ignore_ack
        return cls

    def __init__(self, port: str, timeout: int, baudrate: int, write_timeout: Optional[int] = None):
        """Initialize serial proxy with connection parameters.

        The initialization signature accommodates instantiation compatible with serial.Serial
        interface while providing proxy functionality for testing and simulation purposes.

        :param port: Serial port name or identifier.
        :param timeout: Read timeout value in seconds (stored but not actively used).
        :param baudrate: Serial communication speed in bits per second (stored but not used).
        :param write_timeout: Write timeout value in seconds (stored but not actively used).
        """
        self.port = port
        self.timeout = timeout
        self.write_timeout = write_timeout
        self.baudrate = baudrate
        self.is_open = False
        self.buffer = bytes()

    def open(self) -> None:
        """Simulates opening a serial port.

        This method sets the internal state to indicate that the serial port connection
        is open and ready for communication.
        """
        self.is_open = True

    def close(self) -> None:
        """Simulates closing a serial port.

        This method sets the is_open flag to False to indicate that the serial port
        connection has been closed. No actual hardware communication occurs.
        """
        self.is_open = False

    def write(self, data: bytes) -> None:
        """Simulate a write operation by retrieving response from predefined responses.

        The method simulates writing data to a serial interface by using the input data
        as a key to look up a corresponding response from the responses dictionary. If
        ignore_ack is enabled and the data is an ACK byte sequence, the operation is
        ignored.

        :param data: Bytes to write, used as key to lookup response in responses dict
        :raises KeyError: If data key is not found in responses dictionary
        """
        logger.debug(f"I got: {data!r}")
        if self.ignore_ack and data == b"\x5a\xa1":
            logger.debug("ACK received and ignored")
            return
        self.buffer = self.responses[data]
        logger.debug(f"setting buffer to: '{self.buffer!r}'")

    def read(self, length: int) -> bytes:
        """Read portion of pre-configured data from buffer.

        The method extracts the requested amount of data from the internal buffer
        and removes the read data from the buffer.

        :param length: Amount of data to read from buffer in bytes.
        :return: Data segment read from buffer.
        """
        segment = self.buffer[:length]
        self.buffer = self.buffer[length:]
        logger.debug(f"I responded with: '{segment!r}'")
        return segment

    def __str__(self) -> str:
        """Get string representation of the interface.

        :return: Class name of the interface as string representation.
        """
        return self.__class__.__name__

    def reset_input_buffer(self) -> None:
        """Simulates resetting input buffer.

        This method clears the input buffer to simulate the behavior of a real serial port's
        input buffer reset operation.
        """

    def reset_output_buffer(self) -> None:
        """Simulates resetting output buffer.

        This method clears the output buffer to simulate the behavior of a real serial port's
        output buffer reset operation.
        """

    def flush(self) -> None:
        """Simulates flushing input buffer.

        This method provides a mock implementation of buffer flushing functionality
        for testing or simulation purposes. No actual buffer operations are performed.
        """


class SimpleReadSerialProxy(SerialProxy):
    """Serial proxy for simplified read-only communication simulation.

    This class provides a streamlined approach to simulating serial device
    communication where only read operations need to be mocked. It maintains
    a static buffer of data that can be read sequentially, making it ideal
    for testing scenarios where write operations are ignored and only
    predetermined read responses are required.

    :cvar FULL_BUFFER: Static buffer containing all data to be read sequentially.
    """

    FULL_BUFFER = bytes()

    @classmethod
    def init_data_proxy(cls, data: bytes) -> "Type[SimpleReadSerialProxy]":
        """Initialize data proxy with response buffer.

        This class method sets up the serial proxy with a predefined data buffer
        that will be used for simulating serial communication responses.

        :param data: Byte data to be used as the response buffer for read operations.
        :return: SerialProxy class configured with the provided data buffer.
        """
        cls.FULL_BUFFER = data
        return cls

    def __init__(self, port: str, timeout: int, baudrate: int, write_timeout: Optional[int] = None):
        """Initialize serial proxy with specified communication parameters.

        This constructor sets up the serial proxy by calling the parent serial.Serial
        constructor and initializes the internal buffer to its full capacity.

        :param port: Serial port name or device path.
        :param timeout: Read timeout value in seconds (unused in proxy mode).
        :param baudrate: Serial communication baud rate (unused in proxy mode).
        :param write_timeout: Write timeout value in seconds (unused in proxy mode).
        """
        super().__init__(port=port, timeout=timeout, baudrate=baudrate, write_timeout=write_timeout)
        self.buffer = self.FULL_BUFFER

    def write(self, data: bytes) -> None:
        """Write data to the serial proxy.

        This method simulates a write operation but performs no actual data transmission.
        It serves as a placeholder for testing and simulation purposes.

        :param data: The byte data to be written to the serial interface.
        """
