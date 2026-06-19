#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK UART interface implementation for MBoot protocol communication.

This module provides UART-based communication interface for MBoot protocol,
enabling secure provisioning operations over serial connections.
"""

import logging
from typing import Optional

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol
from spsdk.utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


class MbootUARTInterface(MbootSerialProtocol):
    """SPSDK UART interface for MBoot protocol communication.

    This class provides UART-based communication interface for MBoot protocol operations,
    enabling device discovery, connection management, and data exchange over serial ports.

    :cvar default_baudrate: Default UART communication speed (57600 baud).
    :cvar identifier: Interface type identifier string.
    """

    default_baudrate = 57600
    device: SerialDevice
    identifier = "uart"

    def __init__(self, device: SerialDevice):
        """Initialize the MbootUARTInterface object.

        :param device: The serial device instance to use for UART communication.
        :raises AssertionError: If device is not a SerialDevice instance.
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
        If 'port' is specified, only that serial port is checked.
        If no devices are found, return an empty list.

        :param port: Name of preferred serial port, defaults to None.
        :param baudrate: Speed of the UART interface, defaults to 56700.
        :param timeout: Timeout in milliseconds, defaults to 5000.
        :raises SpsdkNoDeviceFoundError: When a specific port was accessible but did not
            respond to the PING command, indicating the device may not be in bootloader mode.
        :return: List of interfaces responding to the PING command.
        """
        from spsdk.utils.interfaces.protocol.protocol_base import SpsdkNoDeviceFoundError

        baudrate = baudrate or cls.default_baudrate
        devices = SerialDevice.scan(port=port, baudrate=baudrate, timeout=timeout)
        interfaces = []
        ping_failed_ports: list[str] = []
        for device in devices:
            try:
                interface = cls(device)
                interface.open()
                interface._ping()
                interface.close()
                interfaces.append(interface)
            except Exception as e:
                logger.debug(  # pylint: disable=logging-fstring-interpolation
                    f"UART ping failed on port '{device}' at {baudrate} baud: {e}"
                )
                interface.close()
                ping_failed_ports.append(str(device))

        if ping_failed_ports and not interfaces:
            # Port(s) were accessible but device did not respond to ping.
            # Give a specific hint rather than the generic "no devices found" message.
            ports_str = ", ".join(ping_failed_ports)
            baudrate_hint = (
                f" If the device uses a different baud rate, specify it explicitly "
                f"(e.g., '{ping_failed_ports[0]},{baudrate * 2}' or "
                f"'{ping_failed_ports[0]},115200')."
                if baudrate != 115200
                else ""
            )
            raise SpsdkNoDeviceFoundError(
                cls.identifier,
                f"port={ports_str}, baudrate={baudrate}, timeout={timeout}",
                hint=(
                    f"Device found on port(s) {ports_str} but did not respond to PING "
                    f"at {baudrate} baud. Ensure the device is in bootloader mode."
                    f"{baudrate_hint}"
                ),
            )
        return interfaces
