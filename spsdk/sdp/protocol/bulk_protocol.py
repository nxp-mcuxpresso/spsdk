#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP bulk implementation."""
import logging
from typing import Optional

from spsdk.exceptions import SPSDKAttributeError, SPSDKConnectionError
from spsdk.sdp.commands import CmdResponse
from spsdk.sdp.protocol.base import SDPProtocolBase
from spsdk.utils.interfaces.commands import CmdPacketBase

HID_REPORT = {
    # name | id | length
    "CMD": (0x01, 1024, False),
    "DATA": (0x02, 1024, False),
    "HAB": (0x03, 4),
    "RET": (0x04, 64),
}
logger = logging.getLogger(__name__)


class SDPBulkProtocol(SDPProtocolBase):
    """SDP Bulk protocol."""

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
        report_id, report_size, _ = HID_REPORT["DATA"]
        frames = self._create_frames(data=data, report_id=report_id, report_size=report_size)
        for frame in frames:
            self.device.write(frame)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packed contains no data to be sent
        """
        data = packet.to_bytes()
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        report_id, report_size, _ = HID_REPORT["CMD"]
        frames = self._create_frames(data=data, report_id=report_id, report_size=report_size)
        for frame in frames:
            self.device.write(frame)

    def read(self, length: Optional[int] = None) -> CmdResponse:
        """Read data from device.

        :return: read data
        """
        raw_data = self.device.read(1024)
        return self._decode_report(bytes(raw_data))

    def _create_frames(self, data: bytes, report_id: int, report_size: int) -> list[bytes]:
        """Split the data into chunks of max size and encapsulate each of them .

        :param data: Data to send
        :param report_id: ID of the report (see: HID_REPORT)
        :param report_size: Max size of a report
        :return: Encoded bytes and length of the final report frame
        """
        frames: list[bytes] = []
        data_index = 0
        while data_index < len(data):
            try:
                raw_data, data_index = self._create_frame(data, report_id, report_size, data_index)
                frames.append(raw_data)
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e
        return frames

    def _create_frame(
        self, data: bytes, report_id: int, report_size: int, offset: int = 0
    ) -> tuple[bytes, int]:
        """Get the data chunk, encapsulate it into frame and return it with index.

        :param data: Data to send
        :param report_id: ID of the report (see: HID_REPORT)
        :param report_size: Max size of a report
        :return: Encoded bytes and length of the final report frame
        """
        data_len = min(len(data) - offset, report_size)
        raw_data = bytes([report_id])
        raw_data += data[offset : offset + data_len]
        raw_data += bytes([0x00] * (report_size - data_len))
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data, offset + data_len

    @staticmethod
    def _decode_report(raw_data: bytes) -> CmdResponse:
        """Decodes the data read on USB interface.

        :param raw_data: Data received
        :return: CmdResponse object
        """
        if not raw_data:
            raise SPSDKConnectionError("No data were received")
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return CmdResponse(raw_data[0] == HID_REPORT["HAB"][0], raw_data[1:])

    def configure(self, config: dict) -> None:
        """Set HID report data.

        :param config: parameters dictionary
        """
        if "hid_ep1" in config and "pack_size" in config:
            HID_REPORT["CMD"] = (0x01, config["pack_size"], config["hid_ep1"])
            HID_REPORT["DATA"] = (0x02, config["pack_size"], config["hid_ep1"])
