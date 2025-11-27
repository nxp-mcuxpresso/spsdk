#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 UART communication interface.

This module provides low-level UART communication functionality for DK6 devices,
including packet transmission, CRC calculation, and response parsing utilities.
"""

import logging
import struct
from typing import Any, Optional, Union

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.dk6.commands import CmdPacket, CommandTag, parse_cmd_response
from spsdk.dk6.serial_device import SerialDevice
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness

logger = logging.getLogger(__name__)


def calc_crc(data: bytes) -> int:
    """Calculate CRC from the data.

    The method uses CRC32 algorithm to compute the checksum value for the provided data.

    :param data: Data bytes to calculate CRC from.
    :return: Calculated CRC32 checksum as integer value.
    """
    crc_obj = from_crc_algorithm(CrcAlg.CRC32)
    return crc_obj.calculate(data)


def to_int(data: bytes, little_endian: bool = False) -> int:
    """Convert bytes into single integer.

    :param data: Bytes to convert into integer.
    :param little_endian: Indicate byte ordering in data, defaults to False for big endian.
    :return: Converted integer value.
    """
    byte_order = Endianness.LITTLE if little_endian else Endianness.BIG
    return int.from_bytes(data, byteorder=byte_order.value)


class Uart:
    """UART communication interface for DK6 devices.

    This class provides a high-level interface for UART communication with DK6 devices,
    handling frame-based protocol operations including reading, writing, and managing
    connection state through an underlying serial device.

    :cvar FRAME_START_BYTE: Start byte marker for frame protocol.
    :cvar HEADER_SIZE: Total size of the frame header in bytes.
    """

    FRAME_START_BYTE = 0x00

    FLAG_SIZE = 1
    LENGTH_SIZE = 2
    FRAME_TYPE_SIZE = 1
    CHECKSUM_SIZE = 4

    HEADER_SIZE = FLAG_SIZE + LENGTH_SIZE + FRAME_TYPE_SIZE + CHECKSUM_SIZE

    @property
    def is_opened(self) -> bool:
        """Check device connection status.

        :return: True if device is open and connected, False otherwise.
        """
        return self.device.is_opened

    def __init__(
        self,
        device: SerialDevice,
    ) -> None:
        """Initialize the UART interface.

        :param device: Serial device instance for communication.
        :raises McuBootConnectionError: When the device could not be opened.
        """
        self.device = device
        # self.device.baudrate = baudrate

    def open(self) -> None:
        """Open the UART interface.

        :raises SPSDKError: In any case of fail of UART open operation.
        """
        try:
            self.device.open()
        except Exception as exc:
            raise SPSDKError(f"Cannot open UART interface: {exc}") from exc

    def close(self) -> None:
        """Close the UART interface.

        :raises SPSDKError: In any case of fail of UART close operation.
        """
        try:
            self.device.close()
        except Exception as exc:
            raise SPSDKError(f"Cannot close UART interface: {exc}") from exc

    def read(self) -> Any:
        """Read data from device.

        Reads and parses a complete frame from the device, including validation
        of frame structure and CRC checksum.

        :return: Parsed command response object.
        :raises SPSDKError: Did not receive correct frame start byte.
        :raises SPSDKError: When received invalid CRC.
        """
        flag = to_int(self._read_default(self.FLAG_SIZE))
        if flag != self.FRAME_START_BYTE:
            raise SPSDKError("Did not receive correct frame start byte")

        length = to_int(self._read_default(self.LENGTH_SIZE))
        frame_type = to_int(self._read_default(self.FRAME_TYPE_SIZE))

        data = self._read_default(length - self.HEADER_SIZE)
        crc = to_int(self._read_default(self.CHECKSUM_SIZE))

        calculated_crc = self.calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise SPSDKError("Received invalid CRC")

        logger.debug(
            f"<-READ flag: {hex(flag)}, length: {hex(length)}, "
            f"frame_type: {hex(frame_type)}, data: <{' '.join(f'{b:02x}' for b in data)}>,"
            f" crc: {hex(crc)}"
        )
        return parse_cmd_response(data, frame_type)

    def write(self, frame_type: CommandTag, packet: Union[CmdPacket, bytes, None]) -> None:
        """Write data to the device.

        Data might be in form of 'CmdPacket' or bytes. The method automatically converts
        CmdPacket objects to bytes before sending.

        :param frame_type: Command tag specifying the type of frame to create.
        :param packet: Packet data to send, can be CmdPacket object, bytes, or None.
        :raises AttributeError: Frame type is incorrect.
        """
        if isinstance(packet, CmdPacket):
            packet = packet.export()

        frame = self.create_frame(packet, frame_type.tag)
        # logger.debug(f"Packet {packet}, frame type; {frame_type}")
        # logger.debug(f"->WRITE: frame: {frame}")
        self._send_frame(frame)

    def _read_default(self, length: int) -> bytes:
        """Read specified number of bytes from device.

        This function provides default read implementation that can be overridden in child classes
        to customize reading behavior for specific device types.

        :param length: Number of bytes to read from the device.
        :raises SPSDKError: When read operation fails.
        :return: Data read from the device.
        """
        return self._read(length)

    def _read(self, length: int) -> bytes:
        """Read specified number of bytes from device.

        :param length: Number of bytes to read from the device.
        :raises TimeoutError: When no data is received from device (timeout).
        :raises SPSDKError: When reading data from device fails.
        :return: Data read from the device.
        """
        try:
            data = self.device.read(length)
        except Exception as e:
            raise SPSDKError(str(e)) from e
        if not data:
            raise TimeoutError()
        logger.debug(f"<-READ:  <{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _write(self, data: bytes) -> None:
        """Send data to device.

        This method writes the provided byte data to the connected device and logs
        the transmission for debugging purposes.

        :param data: Byte data to be sent to the device.
        :raises SPSDKError: When sending the data fails due to communication issues.
        """
        logger.debug(f"->WRITE: [{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device.write(data)
        except Exception as e:
            raise SPSDKError(str(e)) from e

    def _send_frame(self, frame: bytes) -> None:
        """Send a frame to UART.

        :param frame: Data to send
        :raises SPSDKError: If frame transmission fails
        """
        self._write(frame)

    @staticmethod
    def create_frame(data: Optional[bytes], frame_type: Union[int, CommandTag]) -> bytes:
        """Encapsulate data into frame for UART communication.

        Creates a properly formatted frame with start byte, length, frame type,
        payload data, and CRC checksum for secure transmission.

        :param data: Payload data to be encapsulated, None for frames without payload.
        :param frame_type: Frame type identifier as integer or CommandTag enum.
        :return: Complete frame as bytes ready for transmission.
        """
        frame_type = frame_type if isinstance(frame_type, int) else frame_type.tag
        crc = Uart.calc_frame_crc(data, frame_type)
        if data:
            # print(f"Data length {len(data) + Uart.HEADER_SIZE}")
            frame = struct.pack(
                f">BHB{len(data)}BI",
                Uart.FRAME_START_BYTE,
                len(data) + Uart.HEADER_SIZE,
                frame_type,
                *data,
                crc,
            )
        else:
            frame = struct.pack(
                ">BHBI",
                Uart.FRAME_START_BYTE,
                Uart.HEADER_SIZE,
                frame_type,
                crc,
            )

        return frame

    @staticmethod
    def calc_frame_crc(data: Optional[bytes], frame_type: Union[int, CommandTag]) -> int:
        """Calculate the CRC of a frame.

        The method constructs frame data with header information and calculates CRC checksum
        for UART communication protocol.

        :param data: Frame payload data, None for frames without payload.
        :param frame_type: Frame type identifier as integer or CommandTag enum.
        :return: Calculated CRC checksum as integer value.
        """
        frame_type = frame_type if isinstance(frame_type, int) else frame_type.tag
        if data:
            crc_data = struct.pack(
                f">BHB{len(data)}B",
                Uart.FRAME_START_BYTE,
                len(data) + Uart.HEADER_SIZE,
                frame_type,
                *data,
            )
        else:
            crc_data = struct.pack(
                ">BHB",
                Uart.FRAME_START_BYTE,
                Uart.HEADER_SIZE,
                frame_type,
            )
        return calc_crc(crc_data)
