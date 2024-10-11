#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""CAN Mboot interface implementation."""
import logging
from typing import Optional, Union

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol
from spsdk.utils.interfaces.device.can_device import CANDevice

logger = logging.getLogger(__name__)


class MbootCANInterface(MbootSerialProtocol):
    """UART interface."""

    default_bitrate = 1_000_000
    device: CANDevice
    identifier = "can"

    def __init__(self, device: CANDevice):
        """Initialize the MbootCANInterface object.

        :param device: The device instance
        """
        assert isinstance(device, CANDevice)
        super().__init__(device=device)

    @classmethod
    def scan(
        cls,
        interface: str,
        channel: Optional[Union[str, int]] = None,
        bitrate: Optional[int] = None,
        timeout: Optional[int] = None,
        txid: Optional[int] = None,
        rxid: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected UART devices.

        Returns list of CAN interfaces with devices that respond to PING command.
        If no devices are found, return an empty list.

        :param interface: name of preferred CAN interface
        :param channel: channel of the CAN interface
        :param bitrate: bitrate of the CAN interface
        :param timeout: timeout for the scan
        :param txid: default arbitration ID for TX
        :param rxid: default arbitration ID for RX
        :return: list of interfaces responding to the PING command
        """
        interfaces = []
        bitrate = bitrate or cls.default_bitrate
        devices = CANDevice.scan(interface, channel, bitrate, timeout, txid, rxid)
        for device in devices:
            try:
                can_interface = cls(device)
                can_interface.open()
                can_interface._ping()
                can_interface.close()
                interfaces.append(can_interface)
            except Exception:
                can_interface.close()
        return interfaces
