#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SerialBuspalProxy serves as patch replacement for serial.Serial class."""

import logging
from typing import Optional, Type  # pylint: disable=unused-import  # Type is necessary for Mypy

from spsdk.exceptions import SPSDKError
from spsdk.mboot.interfaces.buspal import I2cModeCommand, SpiModeCommand
from spsdk.utils.serial_proxy import SerialProxy

logger = logging.getLogger(__name__)


class SerialBuspalProxy(SerialProxy):
    """SerialProxy is used to simulate communication with BUSPAL serial device.

    It can be used as mock.patch for serial.Serial class.
    @patch(<your.package>.Serial, SerialProxy.init_proxy(pre_recorded_responses))
    """

    frame_header: int

    @classmethod
    def init_buspal_proxy(cls, target: str, data: dict[bytes, bytes]) -> "Type[SerialProxy]":
        """Initialized response dictionary of write and read bytes.

        :param target: BUSPAL target type
        :param data: Dictionary of write and read bytes
        :return: SerialProxy class with configured data
        :raises SPSDKError: target not supported
        """
        if target == "i2c":
            cls.frame_header = I2cModeCommand.write_then_read.value
        elif target == "spi":
            cls.frame_header = SpiModeCommand.write_then_read.value
        else:
            raise SPSDKError(f"Target {target} not supported")
        return super().init_proxy(data)

    def __init__(self, port: str, timeout: int, baudrate: int, write_timeout: Optional[int] = None):
        """Basic initialization for serial.Serial class.

        __init__ signature must accommodate instantiation of serial.Serial

        :param port: Serial port name
        :param timeout: timeout (does nothing)
        :param baudrate: Serial port speed (does nothing)
        """
        self._buffer_index = 0
        self.tx_buffer = b""
        self.rx_buffer = b""
        super().__init__(port, timeout, baudrate, write_timeout=write_timeout)

    def write(self, data: bytes) -> None:
        """Simulates a BUSPAL write, pick up response from responses, store if command frame.

        Description:
            Command frame length is 5 bytes and start with byte 0x8:
                - if byte 1 is not 0, this is the number of bytes to write, sent as consecutive frames
                - if byte 3 is not 0, this is the number of bytes to read, received from consecutive frames

        :param data: Bytes to write, key in responses
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
        """Read portion of pre-configured data.

        :param length: Amount of data to read from buffer
        :return: Data read
        """
        if isinstance(self.rx_buffer, list):
            segment = self.rx_buffer[self._buffer_index][:length]
            self._buffer_index += 1
        else:
            segment = self.rx_buffer[:length]
        logger.debug(f"<{' '.join(hex(x) for x in segment)}>")
        return segment
