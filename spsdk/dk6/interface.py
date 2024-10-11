#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""DK6 UART communication interface."""
import logging
import struct
from typing import Any, Union

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.dk6.commands import CmdPacket, CommandTag, parse_cmd_response
from spsdk.dk6.serial_device import SerialDevice
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness

logger = logging.getLogger(__name__)


def calc_crc(data: bytes) -> int:
    """Calculate CRC from the data.

    :param data: data to calculate CRC from
    :return: calculated CRC
    """
    crc_obj = from_crc_algorithm(CrcAlg.CRC32)
    return crc_obj.calculate(data)


def to_int(data: bytes, little_endian: bool = False) -> int:
    """Convert bytes into single integer.

    :param data: bytes to convert
    :param little_endian: indicate byte ordering in data, defaults to True
    :return: integer
    """
    byte_order = Endianness.LITTLE if little_endian else Endianness.BIG
    return int.from_bytes(data, byteorder=byte_order.value)


class Uart:
    """UART interface for DK6 devices."""

    FRAME_START_BYTE = 0x00

    FLAG_SIZE = 1
    LENGTH_SIZE = 2
    FRAME_TYPE_SIZE = 1
    CHECKSUM_SIZE = 4

    HEADER_SIZE = FLAG_SIZE + LENGTH_SIZE + FRAME_TYPE_SIZE + CHECKSUM_SIZE

    @property
    def is_opened(self) -> bool:
        """Return True if device is open, False otherwise."""
        return self.device.is_opened

    def __init__(
        self,
        device: SerialDevice,
    ) -> None:
        """Initialize the UART interface.

        :param port: name of the serial port, defaults to None
        :raises McuBootConnectionError: when the port could not be opened
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

        :return: CmdResponse
        :raises SPSDKError: Did not receive correct frame start byte
        :raises SPSDKError: When received invalid CRC
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
        """Write data to the device; data might be in form of 'CmdPacket' or bytes.

        :param frame_type: CommandTag
        :param packet: Packet to send
        :raises AttributeError: frame type is incorrect
        """
        if isinstance(packet, CmdPacket):
            packet = packet.to_bytes()

        frame = self.create_frame(packet, frame_type.tag)
        # logger.debug(f"Packet {packet}, frame type; {frame_type}")
        # logger.debug(f"->WRITE: frame: {frame}")
        self._send_frame(frame)

    def _read_default(self, length: int) -> bytes:
        """Read 'length' amount of bytes from device, this function can be overridden in child class.

        :param length: Number of bytes to read
        :type length: int
        :raises SPSDKError: When read fails
        :return: Data read from the device
        """
        return self._read(length)

    def _read(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises TimeoutError: Time-out
        :raises SPSDKError: When reading data from device fails
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

        :param data: Data to send
        :raises SPSDKError: When sending the data fails
        """
        logger.debug(f"->WRITE: [{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device.write(data)
        except Exception as e:
            raise SPSDKError(str(e)) from e

    def _send_frame(self, frame: bytes) -> None:
        """Send a frame to UART.

        :param frame: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        """
        self._write(frame)

    @staticmethod
    def create_frame(data: Union[bytes, None], frame_type: Union[int, CommandTag]) -> bytes:
        """Encapsulate data into frame.

        :param data: payload data
        :param frame_type: frame type
        :return: frame
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
    def calc_frame_crc(data: Union[bytes, None], frame_type: Union[int, CommandTag]) -> int:
        """Calculate the CRC of a frame.

        :param data: frame data
        :param frame_type: frame type
        :return: calculated CRC
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
