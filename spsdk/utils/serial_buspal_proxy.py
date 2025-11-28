#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Serial Buspal proxy interface for MCU communication.

This module provides a proxy interface that extends SerialProxy functionality
to support Buspal communication protocols including I2C and SPI modes for
NXP MCU interactions.
"""

import logging
from typing import Optional, Type  # pylint: disable=unused-import  # Type is necessary for Mypy

from spsdk.exceptions import SPSDKError
from spsdk.mboot.interfaces.buspal import I2cModeCommand, SpiModeCommand
from spsdk.utils.serial_proxy import SerialProxy

logger = logging.getLogger(__name__)


class SerialBuspalProxy(SerialProxy):
    """Serial BUSPAL proxy for simulating BUSPAL device communication.

    This class extends SerialProxy to provide mock functionality for BUSPAL serial devices,
    supporting I2C and SPI communication protocols. It can be used as a drop-in replacement
    for serial.Serial in testing scenarios with pre-recorded response data.

    :cvar frame_header: Command frame header value based on target protocol type.
    """

    frame_header: int

    @classmethod
    def init_buspal_proxy(cls, target: str, data: dict[bytes, bytes]) -> "Type[SerialProxy]":
        """Initialize BUSPAL proxy with target-specific configuration.

        Sets up the frame header based on the target communication protocol (I2C or SPI)
        and initializes the proxy with the provided data dictionary.

        :param target: BUSPAL target communication protocol ('i2c' or 'spi').
        :param data: Dictionary mapping write bytes to expected read bytes.
        :return: SerialProxy class instance configured with the specified data.
        :raises SPSDKError: Target protocol not supported.
        """
        if target == "i2c":
            cls.frame_header = I2cModeCommand.write_then_read.value
        elif target == "spi":
            cls.frame_header = SpiModeCommand.write_then_read.value
        else:
            raise SPSDKError(f"Target {target} not supported")
        return super().init_proxy(data)

    def __init__(self, port: str, timeout: int, baudrate: int, write_timeout: Optional[int] = None):
        """Initialize serial BusPal proxy connection.

        Basic initialization for serial.Serial class. The __init__ signature must accommodate
        instantiation of serial.Serial for BusPal proxy communication.

        :param port: Serial port name for BusPal connection.
        :param timeout: Connection timeout value (currently not used).
        :param baudrate: Serial port communication speed (currently not used).
        :param write_timeout: Optional write timeout for serial operations.
        """
        self._buffer_index = 0
        self.tx_buffer = b""
        self.rx_buffer = b""
        super().__init__(port, timeout, baudrate, write_timeout=write_timeout)

    def write(self, data: bytes) -> None:
        """Simulate a BUSPAL write operation by processing data and managing response buffers.

        The method handles command frames and data frames differently:
        - Command frames: 5 bytes starting with frame header (0x8)
          - Byte 1 non-zero: number of bytes to write in consecutive frames
          - Byte 3 non-zero: number of bytes to read from consecutive frames
        - Data frames: appended to transmit buffer or used to lookup responses

        :param data: Bytes to write, used as key in responses dictionary
        """
        if len(data) == 5 and data[0] == self.frame_header:
            if data[1]:
                self.tx_buffer += data
            elif data[3]:
                self.tx_buffer = b""
        elif self.tx_buffer:
            # append consecutive transmit bytes
            self.tx_buffer += data
            if self.tx_buffer in self.responses:
                self.rx_buffer = self.responses[self.tx_buffer]
                self._buffer_index = 0
        else:
            # not a command frame, store expected response, defined in pre_recorded_responses
            self.rx_buffer = self.responses[data]
            self._buffer_index = 0
        logger.debug(f"[{' '.join(hex(x) for x in data)}]")

    def read(self, length: int) -> bytes:
        """Read portion of pre-configured data from buffer.

        The method reads data from either a list-based buffer (advancing the buffer index)
        or a single buffer, and logs the read data in hexadecimal format for debugging.

        :param length: Amount of data to read from buffer in bytes.
        :return: Data segment read from the buffer.
        """
        if isinstance(self.rx_buffer, list):
            segment = self.rx_buffer[self._buffer_index][:length]
            self._buffer_index += 1
        else:
            segment = self.rx_buffer[:length]
        logger.debug(f"<{' '.join(hex(x) for x in segment)}>")
        return segment
