#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK CAN interface implementation for MBoot protocol.

This module provides CAN (Controller Area Network) communication interface
for MBoot protocol operations, enabling secure provisioning and device
management over CAN bus networks.
"""

import logging
from typing import Optional, Union

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol
from spsdk.utils.interfaces.device.can_device import CANDevice

logger = logging.getLogger(__name__)


class MbootCANInterface(MbootSerialProtocol):
    """MbootCANInterface for CAN communication with MCU bootloader.

    This class provides CAN (Controller Area Network) interface implementation for
    communicating with NXP MCU bootloaders using the MBoot protocol. It handles
    CAN device scanning, connection management, and protocol communication over
    CAN bus.

    :cvar default_bitrate: Default CAN bus bitrate (1,000,000 bps).
    :cvar identifier: Interface type identifier string.
    """

    default_bitrate = 1_000_000
    device: CANDevice
    identifier = "can"

    def __init__(self, device: CANDevice):
        """Initialize the MbootCANInterface object.

        :param device: The CAN device instance to be used for communication.
        :raises AssertionError: If device is not an instance of CANDevice.
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
        """Scan connected CAN devices.

        Returns list of CAN interfaces with devices that respond to PING command.
        If no devices are found, return an empty list.

        :param interface: Name of preferred CAN interface.
        :param channel: Channel of the CAN interface.
        :param bitrate: Bitrate of the CAN interface.
        :param timeout: Timeout for the scan operation.
        :param txid: Default arbitration ID for TX messages.
        :param rxid: Default arbitration ID for RX messages.
        :return: List of CAN interfaces responding to the PING command.
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
