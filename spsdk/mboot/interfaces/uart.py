#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""UART Mboot interface implementation."""
import logging
from typing import Optional

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol
from spsdk.utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


class MbootUARTInterface(MbootSerialProtocol):
    """UART interface."""

    default_baudrate = 57600
    device: SerialDevice
    identifier = "uart"

    def __init__(self, device: SerialDevice):
        """Initialize the MbootUARTInterface object.

        :param device: The device instance
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
        """Scan connected UART devices.

        Returns list of serial ports with devices that respond to PING command.
        If 'port' is specified, only that serial port is checked
        If no devices are found, return an empty list.

        :param port: name of preferred serial port, defaults to None
        :param baudrate: speed of the UART interface, defaults to 56700
        :param timeout: timeout in milliseconds, defaults to 5000
        :return: list of interfaces responding to the PING command
        """
        baudrate = baudrate or cls.default_baudrate
        devices = SerialDevice.scan(port=port, baudrate=baudrate, timeout=timeout)
        interfaces = []
        for device in devices:
            try:
                interface = cls(device)
                interface.open()
                interface._ping()
                interface.close()
                interfaces.append(interface)
            except Exception:
                interface.close()
        return interfaces
