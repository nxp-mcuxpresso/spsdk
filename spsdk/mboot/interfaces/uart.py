#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for serial communication with a target device using MBoot protocol."""

import logging
import struct
from typing import List, Optional, Tuple, Union

import construct
from crccheck.crc import Crc16
from serial import Serial, SerialException
from serial.tools.list_ports import comports

from spsdk.mboot.commands import CmdPacket, CmdResponse, parse_cmd_response
from spsdk.utils.easy_enum import Enum

from .base import Interface

logger = logging.getLogger("MBOOT:UART")


def scan_uart(port: str = None, baudrate: int = 57600, timeout: int = 5000) -> List[Interface]:
    """Scan connected serial ports.

    Returns list of serial ports with devices that respond to PING command.
    If 'port' is specified, only that serial port is checked
    If no devices are found, return an empty list.

    :param port: name of preferred serial port, defaults to None
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds
    :return: list of interfaces responding to the PING command
    :rtype: List[spsdk.mboot.interfaces.base.Interface]
    """
    if port:
        interface = _check_port(port, baudrate, timeout)
        return [interface] if interface else []
    all_ports = [_check_port(comport.device, baudrate, timeout) for comport in comports(include_links=True)]
    return list(filter(None, all_ports))


def _check_port(port: str, baudrate: int, timeout: int) -> Optional[Interface]:
    """Check if device on comport 'port' responds to PING command.

    :param port: name of port to check
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds
    :return: None if device doesn't respond to PING, instance of Interface if it does
    :rtype: Optional[Interface]
    """
    try:
        interface = Uart(port=port, baudrate=baudrate, timeout=timeout)
        interface.open()
        interface.ping()
        interface.close()
        return interface
    except (AssertionError, SerialException) as e:
        logger.error(str(e))
        return None


def calc_crc(data: bytes) -> int:
    """Calculate CRC from the data.

    :param data: data to calculate CRC from
    :type data: bytes
    :return: calculated CRC
    :rtype: int
    """
    return Crc16.calc(data)


def to_int(data: bytes, little_endian: bool = True) -> int:
    """Convert bytes into single integer.

    :param data: bytes to convert
    :type data: bytes
    :param little_endian: indicate byte ordering in data, defaults to True
    :type little_endian: bool, optional
    :return: integer
    :rtype: int
    """
    byte_order = 'little' if little_endian else 'big'
    return int.from_bytes(data, byteorder=byte_order)

#: Version of protocol used in serial communication
PROTOCOL_VERSION = construct.Struct(
    'bugfix' / construct.Int8ul,
    'minor' / construct.Int8ul,
    'major' / construct.Int8ul,
    'name' / construct.Int8ul
)

#: Type of frame used for pig response
PING_RESPONSE = construct.Struct(
    'version' / PROTOCOL_VERSION,
    'options' / construct.Int16ul,
    'crc' / construct.Int16ul
)


########################################################################################################################
# UART Interface Class
########################################################################################################################
class FPType(Enum):
    """Type of frames used in serial communication."""

    ACK = 0xA1
    NACK = 0xA2
    ABORT = 0xA3
    CMD = 0xA4
    DATA = 0xA5
    PING = 0xA6
    PINGR = 0xA7


class Uart(Interface):
    """UART interface."""

    FRAME_START_BYTE = 0x5A

    @property
    def is_opened(self) -> bool:
        """Return True if device is open, False othervise."""
        return self.device.is_open

    @property
    def need_data_split(self) -> bool:
        """Indicates whether device need to split data into smaller chunks."""
        return True

    def __init__(self, port: str = None, baudrate: int = 57600, timeout: int = 5000) -> None:
        """Initialize the UART interface.

        :param port: name of the serial port, defaults to None
        :type port: str, optional
        :param baudrate: baudrate of the serial port, defaults to 57600
        :type baudrate: int, optional
        :param timeout: read/write timeout in milliseconds, defaults to 2000
        :type timeout: int, optional
        """
        super().__init__()
        self.device = Serial(port=port, timeout=timeout // 1000, baudrate=baudrate)
        self.close()
        self.protocol_version = None
        self.options = None

    def open(self) -> None:
        """Open the UART interface."""
        self.device.open()
        self.ping()

    def close(self) -> None:
        """Close the UART interface."""
        self.device.close()

    def info(self) -> str:
        """Return information about the UART interface.

        :return: Description of UART interface
        :rtype: str
        """
        return self.device.port

    def read(self) -> Union[CmdResponse, bytes]:
        """Read data from device.

        :return: read data
        :rtype: Union[spsdk.mboot.commands.CmdResponse, bytes]
        """
        _, frame_type = self._read_frame_header()
        length = to_int(self._read(2))
        crc = to_int(self._read(2))
        data = self._read(length)
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        assert crc == calculated_crc, "Received invalid CRC"
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data to the device; data might be in form of 'CmdPacket' or bytes.

        :param packet: Packet to send
        :type packet: Union[spsdk.mboot.commands.CmdPacket, bytes]
        """
        if isinstance(packet, CmdPacket):
            data = packet.to_bytes(padding=False)
            frame_type = FPType.CMD
        if isinstance(packet, (bytes, bytearray)):
            data = packet
            frame_type = FPType.DATA
        frame = self._create_frame(data, frame_type)
        self._send_frame(frame, wait_for_ack=True)

    def _read(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :type length: int
        :return: Data read from the device
        :rtype: bytes
        """
        data = self.device.read(length)
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send
        :type data: bytes
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        self.device.reset_input_buffer()
        self.device.reset_output_buffer()
        self.device.write(data)
        self.device.flush()

    def _send_ack(self) -> None:
        ack_frame = struct.pack('<BB', self.FRAME_START_BYTE, FPType.ACK)
        self._send_frame(ack_frame, wait_for_ack=False)

    def _send_frame(self, frame: bytes, wait_for_ack: bool = True) -> None:
        """Send a frame to UART.

        :param frame: Data to send
        :type frame: bytes
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        :type wait_for_ack: bool, optional
        """
        self._write(frame)
        if wait_for_ack:
            self._read_frame_header(FPType.ACK)

    def _read_frame_header(self, expected_frame_type: int = None) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises AssertionError: Unexpected frame header or frame type (if specified)
        """
        header = to_int(self._read(1))
        assert header == self.FRAME_START_BYTE, \
            f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"
        frame_type = to_int(self._read(1))
        if expected_frame_type:
            assert frame_type == expected_frame_type, \
                f"received invalid ACK '{frame_type:#X}' expected '{expected_frame_type:#X}'"
        return header, frame_type

    def _create_frame(self, data: bytes, frame_type: int) -> bytes:
        """Encapsulate data into frame."""
        crc = self._calc_frame_crc(data, frame_type)
        frame = struct.pack(
            f'<BBHH{len(data)}B',
            self.FRAME_START_BYTE, frame_type, len(data), crc, *data)
        return frame

    def _calc_frame_crc(self, data: bytes, frame_type: int) -> int:
        """Calculate the CRC of a frame.

        :param data: frame data
        :type data: bytes
        :param frame_type: frame type
        :type frame_type: int
        :return: calculated CRC
        :rtype: int
        """
        crc_data = struct.pack(
            f'<BBH{len(data)}B',
            self.FRAME_START_BYTE, frame_type, len(data), *data)
        return calc_crc(crc_data)

    def ping(self) -> None:
        """Ping the target device, retreive protocol version.

        :raises AssertionError: If the target device doesn't respond to ping
        """
        ping = struct.pack('<BB', self.FRAME_START_BYTE, FPType.PING)
        self._send_frame(ping, wait_for_ack=False)

        header, frame_type = self._read_frame_header(FPType.PINGR)

        response_data = self._read(8)
        assert response_data, f"Failed to receive ping response"
        response = PING_RESPONSE.parse(response_data)

        # ping response has different crc computation than the other responses
        # that's why we can't use calc_frame_crc method
        # crc data for ping excludes the last 2B of response data, which holds the CRC from device
        crc_data = struct.pack(f'<BB{len(response_data) -2}B', header, frame_type, *response_data[:-2])
        crc = calc_crc(crc_data)
        assert crc == response.crc, \
            f"Received CRC doesn't match"

        self.protocol_version = response.version
        self.options = response.options
