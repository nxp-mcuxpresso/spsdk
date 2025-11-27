#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDIO interface implementation for MBoot protocol communication.

This module provides SDIO (Secure Digital Input Output) interface functionality
for communicating with NXP MCUs using the MBoot protocol through SDIO connections.
"""

import logging
import struct
from sys import platform
from typing import Optional, Union

from typing_extensions import Self

from spsdk.mboot.commands import CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from spsdk.mboot.protocol.serial_protocol import FPType, MbootSerialProtocol
from spsdk.utils.interfaces.device.sdio_device import SdioDevice

logger = logging.getLogger(__name__)

SDIO_DEVICES = {
    # NAME   | VID   | PID
    "RW61x": (0x0471, 0x0209),
}


class MbootSdioInterface(MbootSerialProtocol):
    """SPSDK SDIO interface for MBoot protocol communication.

    This class provides SDIO (Secure Digital Input Output) communication interface
    for MBoot protocol operations, enabling secure provisioning and device
    communication over SDIO connections.

    :cvar identifier: Interface type identifier string.
    :cvar sdio_devices: Dictionary mapping of supported SDIO device configurations.
    """

    identifier = "sdio"
    device: SdioDevice
    sdio_devices = SDIO_DEVICES

    def __init__(self, device: SdioDevice) -> None:
        """Initialize the MbootSdioInterface object.

        :param device: The SDIO device instance to be used for communication.
        :raises SPSDKError: When SDIO interface is used on unsupported Windows platform.
        """
        if platform == "win32":
            logger.warning("Sdio interface is not supported on windows platform.")
        super().__init__(device=device)

    @property
    def name(self) -> str:
        """Get the name of the SDIO device.

        Searches through the known SDIO devices dictionary to find a matching device
        based on vendor ID and product ID, returning the corresponding device name.

        :return: Name of the device if found in known devices, otherwise "Unknown".
        """
        assert isinstance(self.device, SdioDevice)
        for name, value in self.sdio_devices.items():
            if value[0] == self.device.vid and value[1] == self.device.pid:
                return name
        return "Unknown"

    @classmethod
    def scan(
        cls,
        device_path: str,
        timeout: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected SDIO devices.

        :param device_path: Device path string to scan for SDIO devices.
        :param timeout: Interface timeout in seconds, defaults to None for no timeout.
        :return: List of matched SDIO device instances.
        """
        devices = SdioDevice.scan(device_path=device_path, timeout=timeout)
        return [cls(device) for device in devices]

    def open(self) -> None:
        """Open the SDIO interface.

        Establishes connection to the SDIO device and prepares it for communication.

        :raises SPSDKError: If the SDIO device cannot be opened or is not available.
        """
        self.device.open()

    def read(self, length: Optional[int] = None) -> Union[CmdResponse, bytes]:
        """Read data from SDIO interface.

        Reads data frame from the SDIO device, validates CRC, and returns either
        a parsed command response or raw data based on frame type.

        :param length: Optional length parameter (currently unused).
        :raises McuBootConnectionError: Device not opened/available or invalid CRC received.
        :raises McuBootDataAbortError: Reading fails or received empty frame.
        :raises TimeoutError: Timeout occurs during read operation.
        :return: CmdResponse object for command frames or raw bytes for data frames.
        """
        raw_data = self._read(1024)
        if not raw_data:
            logger.error("Cannot read from SDIO device")
            raise TimeoutError()

        _, frame_type = self._parse_frame_header(raw_data)
        _length, crc = struct.unpack_from("<HH", raw_data, 2)
        if not _length:
            self._send_ack()
            raise McuBootDataAbortError()
        data = raw_data[6 : 6 + _length]
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise McuBootConnectionError("Received invalid CRC")
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def _read_frame_header(self, expected_frame_type: Optional[FPType] = None) -> tuple[int, int]:
        """Read frame header and frame type from SDIO interface.

        The method reads 2 bytes from the SDIO interface and parses them to extract
        the frame header and frame type information.

        :param expected_frame_type: Expected frame type to validate against received data.
        :return: Tuple of integers representing frame header and frame type.
        :raises McuBootDataAbortError: Target sends Data Abort frame.
        :raises McuBootConnectionError: Unexpected frame header or frame type.
        :raises McuBootConnectionError: When received invalid ACK.
        """
        data = self._read(2)
        return self._parse_frame_header(data, FPType.ACK)

    def _parse_frame_header(
        self, frame: bytes, expected_frame_type: Optional[FPType] = None
    ) -> tuple[int, int]:
        """Parse frame header and extract frame type from SDIO frame.

        The method validates the frame header against expected start byte and optionally
        checks if the frame type matches the expected type. Handles abort frames and
        connection errors appropriately.

        :param frame: Raw frame data bytes to parse.
        :param expected_frame_type: Expected frame type for validation, optional.
        :return: Tuple of frame header and frame type as integers.
        :raises McuBootDataAbortError: Target sends Data Abort frame.
        :raises McuBootConnectionError: Invalid frame header or unexpected frame type.
        """
        header, frame_type = struct.unpack_from("<BB", frame, 0)
        if header != self.FRAME_START_BYTE:
            raise McuBootConnectionError(
                f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"
            )
        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        if expected_frame_type:
            if frame_type != expected_frame_type:
                raise McuBootConnectionError(
                    f"received invalid ACK '{frame_type:#X}' expected '{expected_frame_type.tag:#X}'"
                )
        return header, frame_type
