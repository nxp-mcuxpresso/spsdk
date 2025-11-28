#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Mboot serial protocol implementation.

This module provides the serial communication protocol implementation for Mboot,
including protocol handling, response parsing, and serial interface management
for NXP MCU bootloader communication.
"""

import logging
import struct
import time
from contextlib import contextmanager
from typing import Generator, NamedTuple, Optional, Union

from typing_extensions import Self

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKAttributeError
from spsdk.mboot.commands import CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.misc import Endianness, Timeout
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class PingResponse(NamedTuple):
    """McuBoot ping command response data structure.

    This NamedTuple represents the structured response from an MCU ping command,
    containing version information, options flags, and CRC validation data.
    """

    version: int
    options: int
    crc: int

    @classmethod
    def parse(cls, data: bytes) -> Self:
        """Parse raw data into PingResponse object.

        The method unpacks binary data containing version, options, and CRC16 checksum
        into a structured PingResponse object using little-endian format.

        :param data: Raw bytes to be unpacked (4B version, 2B options, 2B CRC16).
        :raises McuBootConnectionError: Received invalid ping response format.
        :return: PingResponse object with parsed data.
        """
        try:
            version, options, crc = struct.unpack("<I2H", data)
        except struct.error as err:
            raise McuBootConnectionError("Received invalid ping response") from err
        return cls(version, options, crc)


class FPType(SpsdkEnum):
    """Frame Protocol Type enumeration for serial communication.

    This enumeration defines the different types of frames used in the serial
    communication protocol, including acknowledgment, data transfer, and control frames.
    """

    ACK = (0xA1, "ACK")
    NACK = (0xA2, "NACK")
    ABORT = (0xA3, "ABORT")
    CMD = (0xA4, "CMD")
    DATA = (0xA5, "DATA")
    PING = (0xA6, "PING")
    PINGR = (0xA7, "PINGR")


def to_int(data: bytes, little_endian: bool = True) -> int:
    """Convert bytes into single integer.

    The method converts a byte sequence to an integer value using specified endianness.

    :param data: Bytes to convert to integer.
    :param little_endian: Indicate byte ordering in data, defaults to True.
    :return: Converted integer value.
    """
    byte_order = Endianness.LITTLE if little_endian else Endianness.BIG
    return int.from_bytes(data, byteorder=byte_order.value)


class MbootSerialProtocol(MbootProtocolBase):
    """Mboot Serial Protocol implementation for UART communication.

    This class provides serial communication protocol implementation for Mboot
    operations over UART interface. It handles frame encapsulation, device
    connection management, and protocol-specific communication patterns.

    :cvar FRAME_START_BYTE: Start byte marker for serial frames.
    :cvar PING_TIMEOUT_MS: Timeout in milliseconds for ping operations.
    :cvar MAX_UART_OPEN_ATTEMPTS: Maximum number of attempts to open UART interface.
    """

    FRAME_START_BYTE = 0x5A
    FRAME_START_NOT_READY_LIST = [0x00]
    PING_TIMEOUT_MS = 500
    MAX_PING_RESPONSE_DUMMY_BYTES = 50
    MAX_UART_OPEN_ATTEMPTS = 3
    protocol_version: int = 0
    options: int = 0

    def open(self) -> None:
        """Open the UART interface with retry mechanism.

        Attempts to open the UART device connection up to MAX_UART_OPEN_ATTEMPTS times.
        Each attempt includes opening the device and performing a ping operation to verify
        connectivity. If any attempt fails, the interface is closed before retrying.

        :raises McuBootConnectionError: When UART open operation fails after all retry
            attempts or when an unexpected error occurs during the process.
        """
        for i in range(self.MAX_UART_OPEN_ATTEMPTS):
            try:
                self.device.open()
                self._ping()
                logger.debug(f"Interface opened after {i + 1} attempts.")
                return
            except TimeoutError as e:
                # Closing may take up 30-40 seconds
                self.close()
                logger.debug(f"Timeout when pinging the device: {repr(e)}")
            except McuBootConnectionError as e:
                self.close()
                logger.debug(f"Opening interface failed with: {repr(e)}")
            except Exception as exc:
                self.close()
                raise McuBootConnectionError("Interface open operation fails.") from exc
        raise McuBootConnectionError(
            f"Cannot open UART interface after {self.MAX_UART_OPEN_ATTEMPTS} attempts."
        )

    def close(self) -> None:
        """Close the serial communication interface.

        This method properly closes the underlying serial device connection and releases
        any associated resources.

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

        This method takes raw data bytes, wraps them in a protocol frame with DATA type,
        and transmits the frame to the connected device using the serial interface.

        :param data: Raw data bytes to be encapsulated and transmitted to device.
        """
        frame = self._create_frame(data, FPType.DATA)
        self._send_frame(frame)

    def write_command(self, packet: CmdPacketBase) -> None:
        """Encapsulate command into frames and send them to device.

        :param packet: Command packet object to be sent
        :raises SPSDKAttributeError: Command packet contains no data to be sent
        """
        data = packet.export(padding=False)
        if not data:
            raise SPSDKAttributeError("Incorrect packet type")
        frame = self._create_frame(data, FPType.CMD)
        self._send_frame(frame)

    def read(self, length: Optional[int] = None) -> Union[CmdResponse, bytes]:
        """Read data from device using the serial protocol.

        The method reads a complete frame including header, length, CRC, and data payload.
        It validates the frame integrity and returns either a parsed command response or raw data.

        :param length: Optional parameter (currently unused in implementation).
        :return: Parsed command response if frame type is CMD, otherwise raw data bytes.
        :raises McuBootDataAbortError: Indicates data transmission abort when length is zero.
        :raises McuBootConnectionError: When received CRC doesn't match calculated CRC.
        """
        _, frame_type = self._read_frame_header()
        _length = to_int(self._read(2))
        crc = to_int(self._read(2))
        if not _length:
            self._send_ack()
            raise McuBootDataAbortError()
        data = self._read(_length)
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise McuBootConnectionError("Received invalid CRC")
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def _read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Internal read method for serial protocol communication.

        This method serves as a wrapper around the device's read functionality and is primarily
        designed to be overridden in BUSPAL implementations where different read behavior is required.

        :param length: Number of bytes to read from the device.
        :param timeout: Optional timeout in milliseconds for the read operation.
        :return: Raw bytes data read from the device.
        """
        return self.device.read(length, timeout)

    def _send_ack(self) -> None:
        """Send ACK command.

        Creates and sends an acknowledgment frame to the target device without
        waiting for a response acknowledgment.

        :raises SPSDKError: If frame transmission fails.
        """
        ack_frame = struct.pack("<BB", self.FRAME_START_BYTE, FPType.ACK.tag)
        self._send_frame(ack_frame, wait_for_ack=False)

    def _send_frame(self, frame: bytes, wait_for_ack: bool = True) -> None:
        """Write frame to the device and wait for ack.

        :param frame: Frame data to be sent to the device.
        :param wait_for_ack: Whether to wait for acknowledgment after sending frame.
        """
        self.device.write(frame)
        if wait_for_ack:
            self._read_frame_header(FPType.ACK)

    def _create_frame(self, data: bytes, frame_type: FPType) -> bytes:
        """Encapsulate data into frame with CRC protection.

        Creates a properly formatted frame by adding frame header, CRC checksum,
        and packaging the data according to the protocol specification.

        :param data: Raw data bytes to be encapsulated in the frame.
        :param frame_type: Type of frame to create, determines frame tag value.
        :return: Complete frame bytes ready for transmission.
        """
        crc = self._calc_frame_crc(data, frame_type.tag)
        frame = struct.pack(
            f"<BBHH{len(data)}B",
            self.FRAME_START_BYTE,
            frame_type.tag,
            len(data),
            crc,
            *data,
        )
        return frame

    def _calc_frame_crc(self, data: bytes, frame_type: int) -> int:
        """Calculate the CRC of a frame.

        The method packs frame data with header information and computes CRC checksum
        for the complete frame structure used in serial communication protocol.

        :param data: Frame payload data bytes.
        :param frame_type: Type identifier of the frame.
        :return: Calculated CRC checksum value.
        """
        crc_data = struct.pack(
            f"<BBH{len(data)}B", self.FRAME_START_BYTE, frame_type, len(data), *data
        )
        return self._calc_crc(crc_data)

    @staticmethod
    def _calc_crc(data: bytes) -> int:
        """Calculate CRC from the data.

        The method uses CRC16_XMODEM algorithm to compute the checksum value.

        :param data: Data bytes to calculate CRC from.
        :return: Calculated CRC value as integer.
        """
        crc_ob = from_crc_algorithm(CrcAlg.CRC16_XMODEM)
        return crc_ob.calculate(data)

    def _wait_for_data(self) -> int:
        """Wait for the first frame that is not in the "not ready" state.

        This method continuously reads single bytes from the device until it receives a frame header
        that indicates the device is ready to communicate (not in the "not ready" list).

        :raises McuBootConnectionError: When no data is received within the configured timeout period.
        :return: The header byte of the first frame that is not in the "not ready" state.
        """
        assert isinstance(self.device.timeout, int)
        timeout = Timeout(self.device.timeout, "ms")
        while not timeout.overflow():
            header = to_int(self._read(1))
            if header not in self.FRAME_START_NOT_READY_LIST:
                return header
        raise McuBootConnectionError(f"No data received in {self.device.timeout} ms")

    def _read_frame_header(self, expected_frame_type: Optional[FPType] = None) -> tuple[int, int]:
        """Read frame header and frame type from the communication interface.

        This method handles the protocol-specific frame reading with workaround for SPI ISP
        issue on RT5/6xx where ACK frames and START BYTE frames are sometimes swapped.

        :param expected_frame_type: Expected frame type to validate against received data.
        :return: Tuple of integers representing frame header and frame type.
        :raises McuBootDataAbortError: Target sends Data Abort frame.
        :raises McuBootConnectionError: Unexpected frame header or frame type.
        :raises McuBootConnectionError: When received invalid ACK.
        """
        header = self._wait_for_data()
        # This is workaround addressing SPI ISP issue on RT5/6xx when sometimes
        # ACK frames and START BYTE frames are swapped, see SPSDK-1824 for more details
        if header not in [self.FRAME_START_BYTE, FPType.ACK]:
            raise McuBootConnectionError(
                f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"
                + "\nTry increasing the timeout, some operations might take longer"
            )
        if header == FPType.ACK:
            frame_type: int = header
        else:
            frame_type = to_int(self._read(1))
        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        if expected_frame_type:
            if frame_type == self.FRAME_START_BYTE:
                frame_type = header
            if frame_type != expected_frame_type:
                raise McuBootConnectionError(
                    f"received invalid ACK '{frame_type:#X}' expected '{expected_frame_type.tag:#X}'"
                )
        return header, frame_type

    def _ping(self) -> None:
        """Ping the target device to retrieve protocol version and options.

        Sends a ping frame to the target device and processes the response to establish
        communication and retrieve device capabilities. Handles potential dummy data
        that may be sent by MBoot v3.0+ after power cycle.

        :raises McuBootConnectionError: If the target device doesn't respond to ping
        :raises McuBootConnectionError: If the start frame is not received
        :raises McuBootConnectionError: If the header is invalid
        :raises McuBootConnectionError: If the frame type is invalid
        :raises McuBootConnectionError: If the ping response is not received
        :raises McuBootConnectionError: If crc does not match
        """
        with self.ping_timeout(timeout=max(self.PING_TIMEOUT_MS, self.device.timeout // 10)):
            ping = struct.pack("<BB", self.FRAME_START_BYTE, FPType.PING.tag)

            self._send_frame(ping, wait_for_ack=False)

            # after power cycle, MBoot v 3.0+ may respond to first command with a leading dummy data
            # we read data from UART until the FRAME_START_BYTE byte
            start_byte = b""
            for i in range(self.MAX_PING_RESPONSE_DUMMY_BYTES):
                start_byte = self._read(1)
                if start_byte is None:
                    raise McuBootConnectionError("Failed to receive initial byte")

                if start_byte == self.FRAME_START_BYTE.to_bytes(
                    length=1, byteorder=Endianness.LITTLE.value
                ):
                    logger.debug(f"FRAME_START_BYTE received in {i + 1}. attempt.")
                    break
            else:
                raise McuBootConnectionError("Failed to receive FRAME_START_BYTE")

            header = to_int(start_byte)
            if header != self.FRAME_START_BYTE:
                raise McuBootConnectionError("Header is invalid")
            frame_type = to_int(self._read(1))
            if FPType.from_tag(frame_type) != FPType.PINGR:
                raise McuBootConnectionError("Frame type is invalid")

            response_data = self._read(8)
            if response_data is None:
                raise McuBootConnectionError("Failed to receive ping response")
            response = PingResponse.parse(response_data)

            # ping response has different crc computation than the other responses
            # that's why we can't use calc_frame_crc method
            # crc data for ping excludes the last 2B of response data, which holds the CRC from device
            crc_data = struct.pack(
                f"<BB{len(response_data) -2}B", header, frame_type, *response_data[:-2]
            )
            crc = self._calc_crc(crc_data)
            if crc != response.crc:
                raise McuBootConnectionError("Received CRC doesn't match")

            self.protocol_version = response.version
            self.options = response.options

    @contextmanager
    def ping_timeout(self, timeout: int = PING_TIMEOUT_MS) -> Generator[None, None, None]:
        """Context manager for temporarily changing UART timeout.

        Temporarily sets a new timeout value for the UART device, ensuring it doesn't exceed
        the original timeout. The device driver is reconfigured after timeout changes with
        small delays to ensure proper operation.

        :param timeout: New temporary timeout in milliseconds, defaults to PING_TIMEOUT_MS
        """
        assert isinstance(self.device.timeout, int)
        context_timeout = min(timeout, self.device.timeout)
        original_timeout = self.device.timeout
        self.device.timeout = context_timeout
        logger.debug(f"Setting timeout to {context_timeout} ms")
        # driver needs to be reconfigured after timeout change, wait for a little while
        time.sleep(0.005)

        yield

        self.device.timeout = original_timeout
        logger.debug(f"Restoring timeout to {original_timeout} ms")
        time.sleep(0.005)
