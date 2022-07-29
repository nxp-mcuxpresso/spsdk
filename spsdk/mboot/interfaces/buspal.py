#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for serial communication using BUSPAL protocol, using a FRDM device as translation board."""

import datetime
import logging
import time
from enum import Enum
from typing import List, Optional, Tuple

from serial import SerialException
from serial.tools.list_ports import comports

from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError

from .base import Interface
from .uart import FPType, Uart, to_int

logger = logging.getLogger("MBOOT:BUSPAL")


class BuspalMode(Enum):
    """Bit Bang mode command."""

    reset = 0x00  # Reset, responds "BBIO1"
    spi = 0x01  # Enter binary SPI mode, responds "SPI1"
    i2c = 0x02  # Enter binary I2C mode, responds "I2C1"


class BBConstants(Enum):
    """Constants."""

    reset_count = 20  # Max number of nulls to send to enter BBIO mode
    response_ok = 0x01  # Successful command response
    bulk_transfer_max = 4096  # Max number of bytes per bulk transfer
    packet_timeout_ms = 10  # Packet timeout in milliseconds


class Response(str, Enum):
    """Response to enter bit bang mode."""

    bitbang = "BBIO1"
    spi = "SPI1"
    i2c = "I2C1"


MODE_COMMANDS_RESPONSES = [
    {"mode": BuspalMode.reset, "response": Response.bitbang},
    {"mode": BuspalMode.spi, "response": Response.spi},
    {"mode": BuspalMode.i2c, "response": Response.i2c},
]


class Buspal(Uart):
    """BUSPAL interface."""

    BUSPAL_BAUDRATE = 57600
    DEFAULT_TIMEOUT = 5000

    mode: BuspalMode

    def __init__(self, port: str, timeout: int) -> None:
        """Initialize the BUSPAL interface.

        :param port: uart port of Buspal target
        :param timeout: timeout in milliseconds
        """
        self.timeout = timeout
        super().__init__(port, baudrate=self.BUSPAL_BAUDRATE, timeout=timeout)

    @classmethod
    def check_port(cls, port: str, timeout: int, props: List[str] = None) -> Optional[Interface]:
        """Check if device on comport 'port' can connect using BUSPAL communication protocol.

        :param port: name of port to check
        :param timeout: timeout in milliseconds
        :param props: buspal settings
        :return: None if device doesn't respond to PING, instance of Interface if it does
        """
        props = props if props is not None else []
        try:
            interface = cls(port=port, timeout=timeout)
            interface.open()
            interface.configure(props)
            interface.ping()
            return interface
        except (AssertionError, SerialException, McuBootConnectionError) as e:
            logger.error(str(e))
            return None

    @classmethod
    def scan_buspal(
        cls, port: str = None, timeout: int = DEFAULT_TIMEOUT, props: List[str] = None
    ) -> List[Interface]:
        """Scan connected serial ports and set BUSPAL properties.

        Returns list of serial ports with devices that respond to BUSPAL communication protocol.
        If 'port' is specified, only that serial port is checked
        If no devices are found, return an empty list.

        :param port: name of preferred serial port, defaults to None
        :param timeout: timeout in milliseconds
        :param props: buspal target properties
        :return: list of available interfaces
        """
        if port:
            interface = cls.check_port(port, timeout, props)
            return [interface] if interface else []
        all_ports = [
            cls.check_port(comport.device, timeout, props)
            for comport in comports(include_links=True)
        ]
        return list(filter(None, all_ports))

    def open(self) -> None:
        """Open the BUSPAL interface, configure depending on selected interface."""
        self.device.open()

        # reset first, send bit-bang command
        self.enter_mode(BuspalMode.reset)
        logger.debug("Entered BB mode")
        self.enter_mode(self.mode)

    def _read_frame_header(self, expected_frame_type: int = None) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        :raises McuBootDataAbortError: Abort frame received
        """
        header = None
        time_start = datetime.datetime.now()
        time_end = time_start + datetime.timedelta(milliseconds=self.timeout)

        # read uart until start byte is equal to FRAME_START_BYTE, max. 'retry_count' times
        while header != self.FRAME_START_BYTE and datetime.datetime.now() < time_end:
            header = to_int(self._read_default(1))
            if header == FPType.ABORT:
                raise McuBootDataAbortError()
            if header != self.FRAME_START_BYTE:
                time.sleep(BBConstants.packet_timeout_ms.value / 1000)
        assert (
            header == self.FRAME_START_BYTE
        ), f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"

        frame_type = to_int(self._read_default(1))

        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        return header, frame_type

    def configure(self, props: List[str]) -> None:
        """Configure the BUSPAL interface.

        :param props: buspal settings
        """
        raise NotImplementedError

    def enter_mode(self, mode: BuspalMode) -> None:
        """Enter BUSPAL mode.

        :param mode: buspal mode
        """
        response = next(iter(x["response"] for x in MODE_COMMANDS_RESPONSES if x["mode"] == mode))
        self._send_command_check_response(
            bytes([mode.value]), bytes(response.value.encode("utf-8"))
        )

    def _send_command_check_response(self, command: bytes, response: bytes) -> None:
        """Send a command and check if expected response is received.

        :param command: command to send
        :param response: expected response
        """
        self._write(command)
        data_recvd = self._read(len(response))
        format_received = " ".join(hex(x) for x in data_recvd)
        format_expected = " ".join(hex(x) for x in response)
        assert (
            format_received == format_expected
        ), f"Received data '{format_received}' but expected '{format_expected}'"
