#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP serial implementation."""
import logging
from typing import Optional

from spsdk.exceptions import SPSDKAttributeError
from spsdk.sdp.commands import CmdResponse
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.utils.interfaces.commands import CmdPacketBase

logger = logging.getLogger(__name__)


class SDPSerialProtocol(SDPProtocolBase):
    """SDP Serial protocol."""

    def open(self) -> None:
        """Open the interface."""
        self.device.open()

    def close(self) -> None:
        """Close the interface."""
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return self.device.is_opened

    def write_data(self, data: bytes) -> None:
        """Encapsulate data into frames and send them to device.

        :param data: Data to be sent
        """
        self._send_frame(data)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packed contains no data to be sent
        """
        data = packet.to_bytes()
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        self._send_frame(data)

    def read(self, length: Optional[int] = None) -> CmdResponse:
        """Read data from device.

        :return: read data
        """
        hab_info = self.device.read(length or 4)
        return CmdResponse(self.expect_status, hab_info)

    def _send_frame(self, data: bytes) -> None:
        """Write frame to the device.

        :param data: Data to be send
        """
        self.expect_status = True
        self.device.write(data)
