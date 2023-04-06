#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for serial communication with a target device using MBoot protocol."""

import logging
import struct
import time
from contextlib import contextmanager
from typing import Generator, List, NamedTuple, Optional, Tuple, Union

from crcmod.predefined import mkPredefinedCrcFun
from serial import Serial, SerialTimeoutException
from serial.tools.list_ports import comports

from spsdk.mboot.commands import CmdPacket, CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError
from spsdk.utils.easy_enum import Enum
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import Timeout

from .base import MBootInterface

logger = logging.getLogger(__name__)


def scan_uart(
    port: Optional[str] = None, baudrate: Optional[int] = None, timeout: Optional[int] = None
) -> List["Uart"]:
    """Scan connected serial ports.

    Returns list of serial ports with devices that respond to PING command.
    If 'port' is specified, only that serial port is checked
    If no devices are found, return an empty list.

    :param port: name of preferred serial port, defaults to None
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds, defaults to 5000
    :return: list of interfaces responding to the PING command
    """
    baudrate = baudrate or 57600
    timeout = timeout or 5000
    if port:
        interface = _check_port(port, baudrate, timeout)
        return [interface] if interface else []
    all_ports = [
        _check_port(comport.device, baudrate, timeout) for comport in comports(include_links=True)
    ]
    return list(filter(None, all_ports))


def _check_port(port: str, baudrate: int, timeout: int) -> Optional["Uart"]:
    """Check if device on comport 'port' responds to PING command.

    :param port: name of port to check
    :param baudrate: speed of the UART interface, defaults to 56700
    :param timeout: timeout in milliseconds
    :return: None if device doesn't respond to PING, instance of Interface if it does
    """
    try:
        logger.debug(f"Checking port: {port}, baudrate: {baudrate}, timeout: {timeout}")
        interface = Uart(port=port, baudrate=baudrate, timeout=timeout)
        interface.open()
        interface.close()
        return interface
    except Exception as e:  # pylint: disable=broad-except
        logger.debug(f"{type(e).__name__}: {e}")
        return None


def calc_crc(data: bytes) -> int:
    """Calculate CRC from the data.

    :param data: data to calculate CRC from
    :return: calculated CRC
    """
    crc_function = mkPredefinedCrcFun("xmodem")
    return crc_function(data)


def to_int(data: bytes, little_endian: bool = True) -> int:
    """Convert bytes into single integer.

    :param data: bytes to convert
    :param little_endian: indicate byte ordering in data, defaults to True
    :return: integer
    """
    byte_order = "little" if little_endian else "big"
    return int.from_bytes(data, byteorder=byte_order)  # type: ignore[arg-type]


class PingResponse(NamedTuple):
    """Special type of response for Ping Command."""

    version: int
    options: int
    crc: int

    @classmethod
    def parse(cls, data: bytes) -> "PingResponse":
        """Parse raw data into PingResponse object.

        :param data: bytes to be unpacked to PingResponse object
            4B version, 2B data, 2B CRC16
        :raises McuBootConnectionError: Received invalid ping response
        :return: PingResponse
        """
        try:
            version, options, crc = struct.unpack("<I2H", data)
        except struct.error as err:
            raise McuBootConnectionError("Received invalid ping response") from err
        return cls(version, options, crc)


PING_TIMEOUT_MS = 500
MAX_PING_RESPONSE_DUMMY_BYTES = 50
MAX_UART_OPEN_ATTEMPTS = 3


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


class Uart(MBootInterface):
    """UART interface."""

    FRAME_START_BYTE = 0x5A
    FRAME_START_BYTE_NOT_READY = 0x00

    @property
    def is_opened(self) -> bool:
        """Return True if device is open, False otherwise."""
        return self.device.is_open

    def __init__(
        self, port: Optional[str] = None, baudrate: int = 57600, timeout: int = 5000
    ) -> None:
        """Initialize the UART interface.

        :param port: name of the serial port, defaults to None
        :param baudrate: baudrate of the serial port, defaults to 57600
        :param timeout: read/write timeout in milliseconds, defaults to 5000
        :raises McuBootConnectionError: when the port could not be opened
        """
        super().__init__()
        try:
            self.timeout = timeout
            timeout_s = timeout / 1000
            self.device = Serial(
                port=port, timeout=timeout_s, write_timeout=timeout_s, baudrate=baudrate
            )
            if port:
                self.close()  # TODO: [SPSDK-1212] Is this really necessary here? Please advice somebody.
            self.protocol_version = 0
            self.options = 0
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e

    def open(self) -> None:
        """Open the UART interface.

        :raises McuBootConnectionError: In any case of fail of UART open operation.
        """
        for i in range(MAX_UART_OPEN_ATTEMPTS):
            try:
                self.device.open()
                self.ping()
                logger.debug(f"Interface opened after {i + 1} attempts.")
                return
            except TimeoutError as e:
                self.device.reset_input_buffer()
                self.device.reset_output_buffer()
                # Closing may take up 30-40 seconds
                self.device.close()
                logger.debug(f"Timeout when pinging the device: {repr(e)}")
            except McuBootConnectionError as e:
                self.device.close()
                logger.debug(f"Opening interface failed with: {repr(e)}")
            except Exception as exc:
                self.device.close()
                raise McuBootConnectionError("UART Interface open operation fails.") from exc
        raise McuBootConnectionError(
            f"Cannot open UART interface after {MAX_UART_OPEN_ATTEMPTS} attempts."
        )

    def close(self) -> None:
        """Close the UART interface.

        :raises McuBootConnectionError: In any case of fail of UART close operation.
        """
        try:
            self.device.close()
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e

    def info(self) -> str:
        """Return information about the UART interface.

        :return: Description of UART interface
        :raises McuBootConnectionError: When no port is available
        """
        try:
            return self.device.port
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e

    def read(self) -> Union[CmdResponse, bytes]:
        """Read data from device.

        :return: read data
        :raises McuBootDataAbortError: Indicates data transmission abort
        :raises McuBootConnectionError: When received invalid CRC
        """
        _, frame_type = self._read_frame_header()
        length = to_int(self._read_default(2))
        crc = to_int(self._read_default(2))
        if not length:
            self._send_ack()
            raise McuBootDataAbortError()
        data = self._read_default(length)
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise McuBootConnectionError("Received invalid CRC")
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data to the device; data might be in form of 'CmdPacket' or bytes.

        :param packet: Packet to send
        :raises AttributeError: frame type is incorrect
        """
        data, frame_type = None, None
        if isinstance(packet, CmdPacket):
            data = packet.to_bytes(padding=False)
            frame_type = FPType.CMD
        if isinstance(packet, (bytes, bytearray)):
            data = packet
            frame_type = FPType.DATA
        if not data or not frame_type:
            raise AttributeError("Incorrect packet type")
        frame = self._create_frame(data, frame_type)
        self._send_frame(frame, wait_for_ack=True)

    def _read_default(self, length: int) -> bytes:
        """Read 'length' amount of bytes from device, this function can be overridden in child class.

        :param length: Number of bytes to read
        :type length: int
        :return: Data read from the device
        """
        return self._read(length)

    def _read(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises SPSDKTimeoutError: Time-out
        :raises McuBootConnectionError: When reading data from device fails
        """
        try:
            data = self.device.read(length)
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send
        :raises SPSDKTimeoutError: Time-out
        :raises McuBootConnectionError: When sending the data fails
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device.reset_input_buffer()
            self.device.reset_output_buffer()
            self.device.write(data)
            self.device.flush()
        except SerialTimeoutException as e:
            raise SPSDKTimeoutError(
                f"Write timeout error. The timeout is set to {self.device.write_timeout} s. Consider increasing it."
            ) from e
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e

    def _send_ack(self) -> None:
        ack_frame = struct.pack("<BB", self.FRAME_START_BYTE, FPType.ACK)
        self._send_frame(ack_frame, wait_for_ack=False)

    def _send_frame(self, frame: bytes, wait_for_ack: bool = True) -> None:
        """Send a frame to UART.

        :param frame: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        """
        self._write(frame)
        if wait_for_ack:
            self._read_frame_header(FPType.ACK)

    def _read_frame_header(self, expected_frame_type: Optional[int] = None) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises McuBootDataAbortError: Target sens Data Abort frame
        :raises McuBootConnectionError: Unexpected frame header or frame type (if specified)
        :raises McuBootConnectionError: When received invalid ACK
        """
        timeout = Timeout(self.timeout, "ms")
        header = -1
        while not timeout.overflow():
            header = to_int(self._read_default(1))
            if header != self.FRAME_START_BYTE_NOT_READY:
                break
        # This is workaround addressing SPI ISP issue on RT5/6xx when sometimes
        # ACK frames and START BYTE frames are swapped, see SPSDK-1824 for more details
        if header not in [self.FRAME_START_BYTE, FPType.ACK]:
            raise McuBootConnectionError(
                f"Received invalid frame header '{header:#X}' expected '{self.FRAME_START_BYTE:#X}'"
                + "\nTry increasing the timeout, some operations might take longer"
            )
        if header == FPType.ACK:
            frame_type = header
        else:
            frame_type = to_int(self._read(1))
        if frame_type == FPType.ABORT:
            raise McuBootDataAbortError()
        if expected_frame_type:
            if frame_type == self.FRAME_START_BYTE:
                frame_type = header
            if frame_type != expected_frame_type:
                raise McuBootConnectionError(
                    f"received invalid ACK '{frame_type:#X}' expected '{expected_frame_type:#X}'"
                )
        return header, frame_type

    def _create_frame(self, data: bytes, frame_type: int) -> bytes:
        """Encapsulate data into frame."""
        crc = self._calc_frame_crc(data, frame_type)
        frame = struct.pack(
            f"<BBHH{len(data)}B",
            self.FRAME_START_BYTE,
            frame_type,
            len(data),
            crc,
            *data,
        )
        return frame

    def _calc_frame_crc(self, data: bytes, frame_type: int) -> int:
        """Calculate the CRC of a frame.

        :param data: frame data
        :param frame_type: frame type
        :return: calculated CRC
        """
        crc_data = struct.pack(
            f"<BBH{len(data)}B", self.FRAME_START_BYTE, frame_type, len(data), *data
        )
        return calc_crc(crc_data)

    def ping(self) -> None:
        """Ping the target device, retrieve protocol version.

        :raises McuBootConnectionError: If the target device doesn't respond to ping
        :raises McuBootConnectionError: If the start frame is not received
        :raises McuBootConnectionError: If the header is invalid
        :raises McuBootConnectionError: If the frame type is invalid
        :raises McuBootConnectionError: If the ping response is not received
        :raises McuBootConnectionError: If crc does not match
        """
        with self.ping_timeout(timeout=PING_TIMEOUT_MS):
            ping = struct.pack("<BB", self.FRAME_START_BYTE, FPType.PING)
            self._send_frame(ping, wait_for_ack=False)

            # after power cycle, MBoot v 3.0+ may respond to first command with a leading dummy data
            # we read data from UART until the FRAME_START_BYTE byte
            start_byte = b""
            for i in range(MAX_PING_RESPONSE_DUMMY_BYTES):
                start_byte = self._read_default(1)
                if start_byte is None:
                    raise McuBootConnectionError("Failed to receive initial byte")

                if start_byte == self.FRAME_START_BYTE.to_bytes(length=1, byteorder="little"):
                    logger.debug(f"FRAME_START_BYTE received in {i + 1}. attempt.")
                    break
            else:
                raise McuBootConnectionError("Failed to receive FRAME_START_BYTE")

            header = to_int(start_byte)
            if header != self.FRAME_START_BYTE:
                raise McuBootConnectionError("Header is invalid")
            frame_type = to_int(self._read_default(1))
            if frame_type != FPType.PINGR:
                raise McuBootConnectionError("Frame type is invalid")

            response_data = self._read_default(8)
            if response_data is None:
                raise McuBootConnectionError("Failed to receive ping response")
            response = PingResponse.parse(response_data)

            # ping response has different crc computation than the other responses
            # that's why we can't use calc_frame_crc method
            # crc data for ping excludes the last 2B of response data, which holds the CRC from device
            crc_data = struct.pack(
                f"<BB{len(response_data) -2}B", header, frame_type, *response_data[:-2]
            )
            crc = calc_crc(crc_data)
            if crc != response.crc:
                raise McuBootConnectionError("Received CRC doesn't match")

            self.protocol_version = response.version
            self.options = response.options

    @contextmanager
    def ping_timeout(self, timeout: int = PING_TIMEOUT_MS) -> Generator[None, None, None]:
        """Context manager for changing UART's timeout.

        :param timeout: New temporary timeout in milliseconds, defaults to PING_TIMEOUT_MS (500ms)
        :return: Generator[None, None, None]
        """
        context_timeout = min(timeout, self.timeout)
        context_timeout_s = context_timeout / 1000
        self.device.timeout = context_timeout_s
        self.device.write_timeout = context_timeout_s
        logger.debug(f"Setting timeout to {context_timeout} ms")
        # driver needs to be reconfigured after timeout change, wait for a little while
        time.sleep(0.005)

        yield

        restored_timeout_s = self.timeout / 1000
        self.device.timeout = restored_timeout_s
        self.device.write_timeout = restored_timeout_s
        logger.debug(f"Restoring timeout to {self.timeout} ms")
        time.sleep(0.005)
