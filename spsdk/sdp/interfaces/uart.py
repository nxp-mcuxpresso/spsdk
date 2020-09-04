#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for serial communication with a target device using SDP protocol."""

import logging
from typing import Union, List, Optional

from serial import Serial, SerialException
from serial.tools.list_ports import comports

from spsdk.sdp.commands import CmdPacket, CmdResponse
from .base import Interface

logger = logging.getLogger("SDP:UART")


def scan_uart(port: str = None, baudrate: int = 115200, timeout: int = 5000) -> List[Interface]:
    """Scan connected serial ports.

    Returns list of serial ports with devices that respond to PING command.
    If 'port' is specified, only that serial port is checked
    If no devices are found, return an empty list.

    :param port: name of preferred serial port, defaults to None
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds
    :return: list of interfaces responding to the PING command
    :rtype: List[spsdk.sdp.interfaces.base.Interface]
    """
    if port:
        interface = _check_port(port, baudrate, timeout)
        return [interface] if interface else []
    all_ports = [_check_port(comport.device, baudrate, timeout) for comport in comports(include_links=True)]
    return list(filter(None, all_ports))


def _check_port(port: str, baudrate: int, timeout: int) -> Optional[Interface]:
    """Check if device on comport 'port' could be openned.

    :param port: name of port to check
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds
    :return: None if device can't be openned, instance of Interface if it does
    :rtype: Optional[Interface]
    """
    try:
        interface = Uart(port=port, baudrate=baudrate, timeout=timeout)
        return interface
    except SerialException as e:
        logger.error(str(e))
        return None


########################################################################################################################
# UART Interface Class
########################################################################################################################

class Uart(Interface):
    """UART interface."""

    @property
    def is_opened(self) -> bool:
        """Return True if device is open, False othervise."""
        return self.device.is_open

    def __init__(self, port: str = None, timeout: int = 5000, baudrate: int = 115200):
        """Initialize the UART interface.

        :param port: name of the serial port, defaults to None
        :type port: str, optional
        :param baudrate: speed of the UART interface, defaults to 115200
        :type baudrate: int, optional
        :param timeout: read/write timeout in milliseconds, defaults to 1000
        :type timeout: int, optional
        """
        super().__init__()
        self.device = Serial(port=port, timeout=timeout // 1000, baudrate=baudrate)
        self.expect_status = False

    def open(self) -> None:
        """Open the UART interface."""
        if not self.device.is_open:
            self.device.open()

    def close(self) -> None:
        """Close the UART interface."""
        if self.device.is_open:
            self.device.close()

    def info(self) -> str:
        """Return information about the UART interface."""
        return self.device.port

    def conf(self, config: dict) -> None:
        """Configure device.

        :param config: parameters dictionary
        """
        pass

    def read(self) -> CmdResponse:
        """Read data from device.

        :return: data read from device
        :rtype: spsdk.sdp.commands.CmdResponse
        """
        hab_info = self._read(4)
        # raw_data = self._read(4) if self.expect_status else hab_info
        # return CmdResponse(hab_info, raw_data)
        return CmdResponse(True, hab_info)

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data to the device; data might be in format of 'CmdPacket' or bytes.

        :param packet: Packet to send
        :type packet: Union[spsdk.sdp.commands.CmdPacket, bytes]
        """
        if isinstance(packet, CmdPacket):
            data = packet.to_bytes()
            self.expect_status = False
        else:
            data = packet
            self.expect_status = True
        self._write(data)

    def _read(self, length: int) -> bytes:
        """Read 'length' amount of bytes from the device.

        :param length: Number of bytes to read
        :type length: int
        :return: Data read
        :rtype: bytes
        """
        data = self.device.read(length)
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send
        :type data: bytes
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        self.device.reset_input_buffer()
        self.device.reset_output_buffer()
        self.device.write(data)
        self.device.flush()
