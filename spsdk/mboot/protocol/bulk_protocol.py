#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot bulk protocol implementation.

This module provides the bulk protocol interface for MBoot communication,
enabling efficient data transfer operations between host and target devices.
The module implements the ReportId enumeration for protocol identification
and MbootBulkProtocol class for handling bulk transfer operations.
"""

import logging
from struct import pack, unpack_from
from typing import Optional, Union

from spsdk.exceptions import SPSDKAttributeError
from spsdk.mboot.commands import CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.spsdk_enum import SpsdkEnum


class ReportId(SpsdkEnum):
    """HID Report ID enumeration for bulk protocol communication.

    This enumeration defines the standard HID report identifiers used in bulk
    protocol operations for command and data transfer between host and device.
    """

    CMD_OUT = (0x01, "CMD_OUT")
    CMD_IN = (0x03, "CMD_IN")
    DATA_OUT = (0x02, "DATA_OUT")
    DATA_IN = (0x04, "DATA_IN")


logger = logging.getLogger(__name__)


class MbootBulkProtocol(MbootProtocolBase):
    """Mboot Bulk Protocol implementation for USB/HID communication.

    This class provides bulk transfer protocol implementation for Mboot communication
    over USB HID interfaces. It handles frame encapsulation, data transmission,
    and abort detection for reliable MCU boot operations.
    """

    def open(self) -> None:
        """Open the interface.

        Establishes connection to the bulk protocol device interface.

        :raises SPSDKError: If the device interface fails to open.
        """
        self.device.open()

    def close(self) -> None:
        """Close the interface.

        Closes the underlying device connection and releases any associated resources.
        """
        self.device.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether the bulk protocol interface is open.

        :return: True if interface is open, False otherwise.
        """
        return self.device.is_opened

    def write_data(self, data: bytes) -> None:
        """Encapsulate data into frames and send them to device.

        The method creates a frame from the provided data and sends it to the device.
        If abort functionality is enabled, it first checks for any abort data from the
        device before sending the frame.

        :param data: Data to be sent to the device.
        :raises McuBootConnectionError: If there's a communication error with the device.
        :raises McuBootDataAbortError: If abort data is received from the device.
        """
        frame = self._create_frame(data, ReportId.DATA_OUT)
        abort_data = None
        if self.allow_abort:
            try:
                abort_data = self.device.read(1024, timeout=10)
                logger.debug(f"Read {len(abort_data)} bytes of abort data")
            except TimeoutError:
                logger.debug("Timeout while reading abort data, no data received")
            except Exception as e:
                raise McuBootConnectionError(str(e)) from e
            if abort_data:
                logger.debug(f"{', '.join(f'{b:02X}' for b in abort_data)}")
                raise McuBootDataAbortError()
        self.device.write(frame)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packet contains no data to be sent
        """
        data = packet.export(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        frame = self._create_frame(data, ReportId.CMD_OUT)
        self.device.write(frame)

    def read(self, length: Optional[int] = None) -> Union[CmdResponse, bytes]:
        """Read data from device.

        Reads up to 1024 bytes from the connected device and parses the received frame
        into a command response or raw bytes.

        :param length: Maximum number of bytes to read (currently unused, reads fixed 1024 bytes).
        :return: Parsed command response or raw bytes data from device.
        :raises SPSDKTimeoutError: When timeout occurs or no data can be read from device.
        """
        data = self.device.read(1024)
        if not data:
            logger.error("Cannot read from HID device")
            raise SPSDKTimeoutError()
        return self._parse_frame(bytes(data))

    def _create_frame(self, data: bytes, report_id: ReportId) -> bytes:
        """Encode the USB packet into HID report frame format.

        The method creates a properly formatted HID report frame by adding the report ID,
        reserved byte, data length, and payload data according to the bulk protocol specification.

        :param data: Data payload to be encoded into the frame.
        :param report_id: ID of the report identifying the frame type.
        :return: Encoded frame as bytes ready for USB transmission.
        """
        raw_data = pack("<2BH", report_id.tag, 0x00, len(data))
        raw_data += data
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data

    @staticmethod
    def _parse_frame(raw_data: bytes) -> Union[CmdResponse, bytes]:
        """Parse USB interface frame data into command response or raw data.

        The method decodes raw USB data by extracting report ID, payload length, and data content.
        Returns either a parsed command response object or raw data bytes depending on report type.

        :param raw_data: Raw bytes received from USB interface
        :return: CmdResponse object for command reports or raw bytes for data reports
        :raises McuBootDataAbortError: Transaction aborted by target when payload length is zero
        """
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        report_id, _, plen = unpack_from("<2BH", raw_data)
        if plen == 0:
            raise McuBootDataAbortError()
        data = raw_data[4 : 4 + plen]
        if report_id == ReportId.CMD_IN:
            return parse_cmd_response(data)
        return data
