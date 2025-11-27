#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK UART interface implementation for Serial Download Protocol.

This module provides UART communication interface for SDP operations,
enabling serial communication with NXP MCUs through UART protocol.
"""

import logging
from typing import Optional

from typing_extensions import Self

from spsdk.sdp.protocol.serial_protocol import SDPSerialProtocol
from spsdk.utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


class SdpUARTInterface(SDPSerialProtocol):
    """SDP UART interface for serial communication with NXP MCU devices.

    This class provides UART-based communication interface for Serial Download Protocol (SDP)
    operations. It handles device scanning, connection management, and serial communication
    with NXP microcontrollers supporting SDP over UART.

    :cvar default_baudrate: Default UART communication speed (115200 bps).
    :cvar identifier: Interface type identifier string.
    """

    default_baudrate = 115200
    device: SerialDevice
    identifier = "uart"

    def __init__(self, device: SerialDevice):
        """Initialize the SdpUARTInterface object.

        :param device: The serial device instance to be used for UART communication.
        :raises AssertionError: If device is not an instance of SerialDevice.
        """
        assert isinstance(device, SerialDevice)
        super().__init__(device=device)

    @classmethod
    def scan(
        cls,
        port: Optional[str] = None,
        baudrate: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected serial ports.

        Returns list of serial ports with devices that respond to PING command.
        If 'port' is specified, only that serial port is checked.
        If no devices are found, return an empty list.

        :param port: Name of preferred serial port, defaults to None.
        :param baudrate: Speed of the UART interface, defaults to 56700.
        :param timeout: Timeout in milliseconds, defaults to 5000.
        :return: List of interfaces responding to the PING command.
        """
        baudrate = baudrate or cls.default_baudrate
        devices = SerialDevice.scan(port=port, baudrate=baudrate, timeout=timeout)
        interfaces = []
        for device in devices:
            try:
                interface = cls(device)
                interface.open()
                interface.close()
                interfaces.append(interface)
            except Exception:
                pass
        return interfaces
