#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SerialProxy serves as patch replacement for serial.Serial class."""

import logging

# pylint: disable=unused-import  # Type is necessary for Mypy
from typing import Optional, Type

logger = logging.getLogger(__name__)


class SerialProxy:
    """SerialProxy is used to simulate communication with serial device.

    It can be used as mock.patch for serial.Serial class.
    @patch(<your.package>.Serial, SerialProxy.init_proxy(pre_recorded_responses))
    """

    responses: dict[bytes, bytes] = {}
    ignore_ack: bool = False

    @classmethod
    def init_proxy(cls, data: dict[bytes, bytes], ignore_ack: bool = False) -> "Type[SerialProxy]":
        """Initialized response dictionary of write and read bytes.

        :param data: Dictionary of write and read bytes
        :param ignore_ack: Don't modify internal buffer upon receiving a ACK packet
        :return: SerialProxy class with configured data
        """
        cls.responses = data
        cls.ignore_ack = ignore_ack
        return cls

    def __init__(self, port: str, timeout: int, baudrate: int, write_timeout: Optional[int] = None):
        """Basic initialization for serial.Serial class.

        __init__ signature must accommodate instantiation of serial.Serial

        :param port: Serial port name
        :param timeout: timeout (does nothing)
        :param write_timeout: does nothing
        :param baudrate: Serial port speed (does nothing)
        """
        self.port = port
        self.timeout = timeout
        self.write_timeout = write_timeout
        self.baudrate = baudrate
        self.is_open = False
        self.buffer = bytes()

    def open(self) -> None:
        """Simulates opening a serial port."""
        self.is_open = True

    def close(self) -> None:
        """Simulates closing a serial port."""
        self.is_open = False

    def write(self, data: bytes) -> None:
        """Simulates a write, currently just pick up response from responses.

        :param data: Bytes to write, key in responses
        """
        logger.debug(f"I got: {data!r}")
        if self.ignore_ack and data == b"\x5a\xa1":
            logger.debug("ACK received and ignored")
            return
        self.buffer = self.responses[data]
        logger.debug(f"setting buffer to: '{self.buffer!r}'")

    def read(self, length: int) -> bytes:
        """Read portion of pre-configured data.

        :param length: Amount of data to read from buffer
        :return: Data read
        """
        segment = self.buffer[:length]
        self.buffer = self.buffer[length:]
        logger.debug(f"I responded with: '{segment!r}'")
        return segment

    def __str__(self) -> str:
        """Text information about the interface."""
        return self.__class__.__name__

    def reset_input_buffer(self) -> None:
        """Simulates resetting input buffer."""

    def reset_output_buffer(self) -> None:
        """Simulates resetting output buffer."""

    def flush(self) -> None:
        """Simulates flushing input buffer."""


class SimpleReadSerialProxy(SerialProxy):
    """SimpleReadSerialProxy is used to simulate communication with serial device.

    It simplifies reading method.
    @patch(<your.package>.Serial, SerialProxy.init_proxy(pre_recorded_responses))
    """

    FULL_BUFFER = bytes()

    @classmethod
    def init_data_proxy(cls, data: bytes) -> "Type[SimpleReadSerialProxy]":
        """Initialized response dictionary of write and read bytes.

        :param data: Dictionary of write and read bytes
        :return: SerialProxy class with configured data
        """
        cls.FULL_BUFFER = data
        return cls

    def __init__(self, port: str, timeout: int, baudrate: int, write_timeout: Optional[int] = None):
        """Basic initialization for serial.Serial class.

        __init__ signature must accommodate instantiation of serial.Serial

        :param port: Serial port name
        :param timeout: timeout (does nothing)
        :param write_timeout: does nothing
        :param baudrate: Serial port speed (does nothing)
        """
        super().__init__(port=port, timeout=timeout, baudrate=baudrate, write_timeout=write_timeout)
        self.buffer = self.FULL_BUFFER

    def write(self, data: bytes) -> None:
        """Simulates a write method, but it does nothing.

        :param data: Bytes to write, key in responses
        """
