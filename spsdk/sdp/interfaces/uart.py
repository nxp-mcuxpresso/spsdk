#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for serial communication with a target device using SDP protocol."""

import logging
from typing import List, Optional, Union

from serial import Serial
from serial.tools.list_ports import comports

from spsdk.sdp.commands import CmdPacket, CmdResponse
from spsdk.sdp.exceptions import SdpConnectionError

from .base import SDPInterface

logger = logging.getLogger(__name__)


def scan_uart(port: str = None, baudrate: int = None, timeout: int = None) -> List["Uart"]:
    """Scan connected serial ports.

    Returns list of serial ports with devices that respond to PING command.
    If 'port' is specified, only that serial port is checked
    If no devices are found, return an empty list.

    :param port: name of preferred serial port, defaults to None
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds, defaults to 5000
    :return: list of interfaces responding to the PING command
    """
    baudrate = baudrate or 115200
    timeout = timeout or 5000
    if port:
        interface = _check_port(port, baudrate, timeout)
        return [interface] if interface else []
    all_ports = [
        _check_port(comport.device, baudrate, timeout) for comport in comports(include_links=True)
    ]
    return list(filter(None, all_ports))


def _check_port(port: str, baudrate: int, timeout: int) -> Optional["Uart"]:
    """Check if device on comport 'port' could be openned.

    :param port: name of port to check
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds
    :return: None if device can't be openned, instance of Interface if it does
    """
    try:
        logger.debug(f"Checking port: {port}, baudrate: {baudrate}, timeout: {timeout}")
        interface = Uart(port=port, baudrate=baudrate, timeout=timeout)
        return interface
    except Exception as e:  # pylint: disable=broad-except
        logger.error(str(e))
        return None


########################################################################################################################
# UART Interface Class
########################################################################################################################


class Uart(SDPInterface):
    """UART interface."""

    @property
    def is_opened(self) -> bool:
        """Return True if device is open, False othervise."""
        return self.device.is_open

    def __init__(self, port: str = None, timeout: int = 5000, baudrate: int = 115200):
        """Initialize the UART interface.

        :param port: name of the serial port, defaults to None
        :param baudrate: speed of the UART interface, defaults to 115200
        :param timeout: read/write timeout in milliseconds, defaults to 1000
        :raises SdpConnectionError: when there is no port available
        """
        super().__init__()
        try:
            self.device = Serial(port=port, timeout=timeout / 1000, baudrate=baudrate)
            self.expect_status = True
        except Exception as e:
            raise SdpConnectionError(str(e)) from e

    def open(self) -> None:
        """Open the UART interface.

        :raises SdpConnectionError: when opening device fails
        """
        if not self.device.is_open:
            try:
                self.device.open()
            except Exception as e:
                raise SdpConnectionError(str(e)) from e

    def close(self) -> None:
        """Close the UART interface.

        :raises SdpConnectionError: when closing device fails
        """
        if self.device.is_open:
            try:
                self.device.close()
            except Exception as e:
                raise SdpConnectionError(str(e)) from e

    def info(self) -> str:
        """Return information about the UART interface.

        :return: information about the UART interface
        :raises SdpConnectionError: when information can not be collected from device
        """
        try:
            return self.device.port
        except Exception as e:
            raise SdpConnectionError(str(e)) from e

    def conf(self, config: dict) -> None:
        """Configure device.

        :param config: parameters dictionary
        """

    def read(self, length: int = None) -> CmdResponse:
        """Read data from device.

        :return: data read from device
        """
        hab_info = self._read(length or 4)
        # raw_data = self._read(4) if self.expect_status else hab_info
        # return CmdResponse(hab_info, raw_data)
        return CmdResponse(self.expect_status, hab_info)

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data to the device; data might be in format of 'CmdPacket' or bytes.

        :param packet: Packet to send
        """
        self.expect_status = True
        if isinstance(packet, CmdPacket):
            data = packet.to_bytes()
        else:
            data = packet
        self._write(data)

    def _read(self, length: int) -> bytes:
        """Read 'length' amount of bytes from the device.

        :param length: Number of bytes to read
        :return: Data read
        :raises SdpConnectionError: when read from device fails
        """
        try:
            data = self.device.read(length)
            if not data:
                raise Exception("No response from SDP device.")
            logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
            return data
        except Exception as e:
            raise SdpConnectionError(str(e)) from e

    def _write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send
        :raises SdpConnectionError: when send data to device fails
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device.reset_input_buffer()
            self.device.reset_output_buffer()
            self.device.write(data)
            self.device.flush()
        except Exception as e:
            raise SdpConnectionError(str(e)) from e
