#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP serial protocol implementation.

This module provides the serial communication protocol implementation for
Serial Download Protocol (SDP) operations, enabling communication with NXP
MCUs over serial interfaces.
"""

import logging
from typing import Optional

from spsdk.exceptions import SPSDKAttributeError
from spsdk.sdp.commands import CmdResponse, CommandTag
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.utils.interfaces.commands import CmdPacketBase

logger = logging.getLogger(__name__)


class SDPSerialProtocol(SDPProtocolBase):
    """SDP Serial protocol implementation for NXP MCU communication.

    This class provides a concrete implementation of the SDP (Serial Download Protocol)
    for serial communication interfaces. It handles frame encapsulation, command
    transmission, and response reading over serial connections to NXP microcontrollers.
    """

    def open(self) -> None:
        """Open the interface.

        Establishes connection to the serial device and prepares it for communication.

        :raises SPSDKConnectionError: If the device cannot be opened or is already in use.
        :raises SPSDKError: If there's a general communication error during opening.
        """
        self.device.open()

    def close(self) -> None:
        """Close the serial communication interface.

        This method properly closes the underlying serial device connection,
        ensuring all resources are released and the communication channel is
        terminated cleanly.

        :raises SPSDKError: If closing the device fails.
        """
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether the serial interface is open.

        :return: True if the interface is open, False otherwise.
        """
        return self.device.is_opened

    def write_data(self, data: bytes) -> None:
        """Encapsulate data into frames and send them to device.

        :param data: Data to be sent to the device.
        """
        self._send_frame(data)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        The method exports the command packet data and sends it as a frame to the device.
        For certain commands (excluding SET_BAUDRATE), it sets the expectation for a status response.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packet contains no data to be sent
        """
        data = packet.export()
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")

        if int.from_bytes(packet.export()[:4], "little") not in [CommandTag.SET_BAUDRATE.tag]:
            self.expect_status = True

        self._send_frame(data)

    def read(self, length: Optional[int] = None) -> CmdResponse:
        """Read data from device.

        Reads HAB (High Assurance Boot) information from the connected device
        and wraps it in a command response object.

        :param length: Number of bytes to read from device, defaults to 4 if not specified.
        :return: Command response object containing the expected status and HAB information.
        """
        hab_info = self.device.read(length or 4)
        return CmdResponse(self.expect_status, hab_info)

    def _send_frame(self, data: bytes) -> None:
        """Write frame to the device.

        :param data: Data to be sent to the device.
        """
        self.device.write(data)
