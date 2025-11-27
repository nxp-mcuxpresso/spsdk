#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SDP bulk protocol implementation for secure device communication.

This module provides the SDPBulkProtocol class that implements bulk transfer
protocol for Serial Download Protocol (SDP) operations, enabling efficient
data transfer with NXP MCU devices during provisioning and programming tasks.
"""

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
    """SDP Bulk Protocol implementation for NXP MCU communication.

    This class provides bulk transfer protocol implementation for Serial Download Protocol (SDP)
    communication with NXP microcontrollers. It handles frame creation, data encapsulation,
    and command/response processing over bulk transfer interfaces.
    """

    def open(self) -> None:
        """Open the interface.

        Establishes connection to the underlying device for communication.

        :raises SPSDKError: If the device cannot be opened or is already in use.
        """
        self.device.open()

    def close(self) -> None:
        """Close the interface.

        Closes the underlying device connection and releases any associated resources.
        """
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether the interface is open.

        :return: True if interface is open, False otherwise.
        """
        return self.device.is_opened

    def write_data(self, data: bytes) -> None:
        """Encapsulate data into frames and send them to device.

        The method breaks down the input data into HID report frames using the DATA report
        configuration and transmits each frame sequentially to the connected device.

        :param data: Binary data to be sent to the device.
        :raises SPSDKError: If device write operation fails.
        """
        report_id, report_size, _ = HID_REPORT["DATA"]
        frames = self._create_frames(data=data, report_id=report_id, report_size=report_size)
        for frame in frames:
            self.device.write(frame)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packet contains no data to be sent
        """
        data = packet.export()
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        report_id, report_size, _ = HID_REPORT["CMD"]
        frames = self._create_frames(data=data, report_id=report_id, report_size=report_size)
        for frame in frames:
            self.device.write(frame)

    def read(self, length: Optional[int] = None) -> CmdResponse:
        """Read data from device.

        Reads raw data from the device and decodes it into a command response format.
        The method reads up to 1024 bytes from the device and processes the response.

        :param length: Maximum number of bytes to read (currently unused, reserved for future use).
        :return: Decoded command response from the device.
        """
        raw_data = self.device.read(1024)
        return self._decode_report(bytes(raw_data))

    def _create_frames(self, data: bytes, report_id: int, report_size: int) -> list[bytes]:
        """Split the data into chunks of max size and encapsulate each of them.

        The method processes input data by dividing it into frames that fit within the specified
        report size constraints, with each frame properly encapsulated according to the protocol.

        :param data: Data to send
        :param report_id: ID of the report (see: HID_REPORT)
        :param report_size: Max size of a report
        :raises SPSDKConnectionError: Frame creation fails
        :return: List of encoded frame bytes
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
        """Create HID report frame from data chunk with proper padding.

        The method takes a data chunk starting at the specified offset, encapsulates it into a HID
        report frame with the given report ID, and pads it to the required report size.

        :param data: Raw data bytes to be encapsulated into the frame.
        :param report_id: HID report identifier to be used in the frame header.
        :param report_size: Maximum size of the HID report frame in bytes.
        :param offset: Starting position in the data buffer for this chunk.
        :return: Tuple containing the encoded frame bytes and the next data offset.
        """
        data_len = min(len(data) - offset, report_size)
        raw_data = bytes([report_id])
        raw_data += data[offset : offset + data_len]
        raw_data += bytes([0x00] * (report_size - data_len))
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data, offset + data_len

    @staticmethod
    def _decode_report(raw_data: bytes) -> CmdResponse:
        """Decode raw data received from USB interface into command response.

        The method parses the raw bytes from USB communication and creates a CmdResponse
        object based on the HAB report format.

        :param raw_data: Raw bytes data received from USB interface
        :raises SPSDKConnectionError: When no data were received
        :return: Parsed command response object
        """
        if not raw_data:
            raise SPSDKConnectionError("No data were received")
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return CmdResponse(raw_data[0] == HID_REPORT["HAB"][0], raw_data[1:])

    def configure(self, config: dict) -> None:
        """Configure HID report data with communication parameters.

        The method updates the global HID_REPORT dictionary with command and data endpoint
        configurations based on the provided parameters.

        :param config: Configuration dictionary containing 'hid_ep1' and 'pack_size' keys
            for HID endpoint and packet size settings
        """
        if "hid_ep1" in config and "pack_size" in config:
            HID_REPORT["CMD"] = (0x01, config["pack_size"], config["hid_ep1"])
            HID_REPORT["DATA"] = (0x02, config["pack_size"], config["hid_ep1"])
