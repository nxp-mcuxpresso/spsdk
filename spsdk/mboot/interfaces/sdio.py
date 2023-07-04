#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for serial communication with a target device using MBoot protocol."""

import logging
import os
import struct
import time
from io import FileIO
from typing import List, Optional, Tuple, Union

from crcmod.predefined import mkPredefinedCrcFun

from spsdk.mboot.commands import CmdPacket, CmdResponse, parse_cmd_response
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError, McuBootError
from spsdk.utils.easy_enum import Enum
from spsdk.utils.misc import Timeout

from .base import MBootInterface

logger = logging.getLogger(__name__)

########################################################################################################################
# Devices
########################################################################################################################

SDIO_DEVICES = {
    # NAME   | VID   | PID
    "RW61x": (0x0471, 0x0209),
}


def scan_sdio(device_path: Optional[str] = None) -> List["Sdio"]:
    """Scan connected SDIO devices.

    :param device_path: device path string
    :return: matched SDIO device
    """
    if device_path is None:
        logger.debug("No sdio path")
        return []
    try:
        logger.debug(f"Checking path: {device_path}")
        interface = Sdio(path=device_path)
        interface.open()
        interface.close()
        return [interface] if interface else []
    except Exception as e:  # pylint: disable=broad-except
        logger.debug(f"{type(e).__name__}: {e}")
        return []


def calc_crc(data: bytes) -> int:
    """Calculate CRC from the data.

    :param data: data to calculate CRC from
    :return: calculated CRC
    """
    crc_function = mkPredefinedCrcFun("xmodem")
    return crc_function(data)


########################################################################################################################
# SDIO Interface Class
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


class Sdio(MBootInterface):
    """SDIO interface."""

    FRAME_START_BYTE = 0x5A
    FRAME_START_BYTE_NOT_READY = 0x00

    @property
    def name(self) -> str:
        """Get the name of the device.

        :return: Name of the device.
        """
        for name, value in SDIO_DEVICES.items():
            if value[0] == self.vid and value[1] == self.pid:
                return name
        return "Unknown"

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False othervise.
        """
        return self.device is not None and self._opened

    def __init__(self, path: Optional[str] = None) -> None:
        """Initialize the SDIO interface object.

        :raises McuBootConnectionError: when the path is empty
        """
        super().__init__()
        self._opened = False
        # Temporarily use hard code until there is a way to retrive VID/PID
        self.vid = 0x0471
        self.pid = 0x0209
        self.timeout = 2000
        if path is None:
            raise McuBootConnectionError("No SDIO device path")
        self.path = path
        self.is_blocking = False
        self.device: Optional[FileIO] = None

    def info(self) -> str:
        """Return information about the SDIO interface."""
        return f"{self.name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"

    def open(self) -> None:
        """Open the interface with non-blocking mode.

        :raises McuBootError: if non-blocking mode is not available
        :raises McuBootConnectionError: if no device path is available
        :raises McuBootConnectionError: if no device is available
        :raises McuBootConnectionError: if the device can not be opened
        """
        if self.is_blocking:
            logger.debug("open with blocking mode")
            self.open_blocking()
            return

        logger.debug("Open Interface with non-blocking mode.")
        if not hasattr(os, "set_blocking"):
            raise McuBootError("Opening in non-blocking mode is available only on Linux")
        if not self._opened:
            try:
                self.device = open(self.path, "rb+", buffering=0)
                if self.device is None:
                    raise McuBootConnectionError("No device available")
                # pylint: disable=no-member     # this is available only on Unix
                os.set_blocking(self.device.fileno(), False)  # type: ignore
                self._opened = True
            except Exception as error:
                raise McuBootConnectionError(
                    f"Unable to open device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def open_blocking(self) -> None:
        """Open the interface with blocking mode.

        :raises McuBootConnectionError: if no device is available
        :raises McuBootConnectionError: if the device can not be opened
        """
        logger.debug("Open Interface")
        if not self._opened:
            try:
                self.device = open(self.path, "rb+", buffering=0)
                self._opened = True
            except Exception as error:
                raise McuBootConnectionError(
                    f"Unable to open device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def close(self) -> None:
        """Close the interface.

        :raises McuBootConnectionError: if no device is available
        :raises McuBootConnectionError: if the device can not be opened
        """
        logger.debug("Close Interface")
        if not self.device:
            raise McuBootConnectionError("No device available")
        if self._opened:
            try:
                self.device.close()
                self._opened = False
            except Exception as error:
                raise McuBootConnectionError(
                    f"Unable to close device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data to the SDIO interface; data might be in form of 'CmdPacket' or bytes.

        :param packet: Data to send
        :raises McuBootError: Raises an error if packet type is incorrect
        :raises McuBootConnectionError: Raises an error if device is not opened for writing
        :raises McuBootConnectionError: Raises an error if device is not available
        """
        if not self.device:
            raise McuBootConnectionError("No device available")
        if not self.is_opened:
            raise McuBootConnectionError("Device is opened for writing")

        if isinstance(packet, CmdPacket):
            data = packet.to_bytes(padding=False)
            frame_type = FPType.CMD
        elif isinstance(packet, (bytes, bytearray)):
            data = packet
            frame_type = FPType.DATA
        else:
            raise McuBootError("Packet has to be either 'CmdPacket' or 'bytes'")

        frame = self._create_frame(data, frame_type)
        self._send_frame(frame, wait_for_ack=True)

    def _write(self, data: bytes) -> None:
        """Send data to device with non-blocking mode.

        :param data: Data to send
        :raises McuBootConnectionError: Raises an error if device is not available
        :raises McuBootConnectionError: When sending the data fails
        :raises TimeoutError: When timeout occurs
        """
        if not self.device:
            raise McuBootConnectionError("No device available")

        if self.is_blocking:
            logger.debug("_write with blocking mode")
            self._write_blocking(data)
            return

        logger.debug("_write with non-blocking mode")
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        tx_len = len(data)
        timeout = Timeout(self.timeout)
        while tx_len > 0:
            try:
                wr_count = self.device.write(data)
                time.sleep(0.05)
                data = data[wr_count:]
                tx_len -= wr_count
            except Exception as e:
                raise McuBootConnectionError(str(e)) from e
            if timeout.overflow():
                raise TimeoutError()

    def _write_blocking(self, data: bytes) -> None:
        """Send data to device with blocking mode.

        :param data: Data to send
        :raises McuBootConnectionError: Raises an error if device is not available
        :raises McuBootConnectionError: When sending the data fails
        """
        if not self.device:
            raise McuBootConnectionError("No device available")

        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device.write(data)
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e

    def read(self) -> Union[CmdResponse, bytes]:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        :raises McuBootConnectionError: Raises an error if device is not opened for reading
        :raises McuBootConnectionError: Raises if device is not available
        :raises McuBootDataAbortError: Raises if reading fails
        :raises TimeoutError: When timeout occurs
        """
        if not self.is_opened:
            raise McuBootConnectionError("Device is not opened for reading")
        if not self.device:
            raise McuBootConnectionError("Device not available")

        raw_data = self._read(1024)
        if not raw_data:
            logger.error("Cannot read from SDIO device")
            raise TimeoutError()

        _, frame_type = self._parse_frame_header(raw_data)
        length, crc = struct.unpack_from("<HH", raw_data, 2)
        if not length:
            self._send_ack()
            raise McuBootDataAbortError()
        data = raw_data[6 : 6 + length]
        self._send_ack()
        calculated_crc = self._calc_frame_crc(data, frame_type)
        if crc != calculated_crc:
            raise McuBootConnectionError("Received invalid CRC")
        if frame_type == FPType.CMD:
            return parse_cmd_response(data)
        return data

    def _read(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device with non-blocking mode.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises TimeoutError: When timeout occurs
        :raises McuBootConnectionError: When reading data from device fails
        :raises McuBootConnectionError: Raises if device is not available
        """
        if not self.device:
            raise McuBootConnectionError("Device not available")

        if self.is_blocking:
            logger.debug("_read with blocking mode")
            data = self._read_blocking(length)
            return data

        has_data = 0
        no_data_continuous = 0
        logger.debug("_read with non-blocking mode")
        data = bytearray()
        timeout = Timeout(self.timeout, "ms")
        while len(data) < length:
            try:
                buf = self.device.read(length)
            except Exception as e:
                raise McuBootConnectionError(str(e)) from e

            if buf is None:
                time.sleep(0.05)  # delay for access device
                if has_data != 0:
                    no_data_continuous = no_data_continuous + 1
            else:
                data.extend(buf)
                logger.debug("expend buf")
                has_data = has_data + 1
                no_data_continuous = 0

            if no_data_continuous > 5:
                break
            if timeout.overflow():
                logger.debug("SDIO interface : read timeout")
                break
        if not data:
            raise TimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return bytes(data)

    def _read_blocking(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device with blocking mode.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises TimeoutError: When timeout occurs
        :raises McuBootConnectionError: When reading data from device fails
        :raises McuBootConnectionError: Raises if device is not available
        """
        if not self.device:
            raise McuBootConnectionError("Device not available")

        try:
            data = self.device.read(length)
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e
        if not data:
            raise TimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _send_ack(self) -> None:
        ack_frame = struct.pack("<BB", self.FRAME_START_BYTE, FPType.ACK)
        self._send_frame(ack_frame, wait_for_ack=False)

    def _send_frame(self, frame: bytes, wait_for_ack: bool = True) -> None:
        """Send a frame to SDIO.

        :param frame: Data to send
        :param wait_for_ack: Wait for ACK frame from device, defaults to True
        """
        self._write(frame)
        if wait_for_ack:
            data = self._read(2)
            self._parse_frame_header(data, FPType.ACK)

    def _parse_frame_header(
        self, frame: bytes, expected_frame_type: Optional[int] = None
    ) -> Tuple[int, int]:
        """Read frame header and frame type. Return them as tuple of integers.

        :param expected_frame_type: Check if the frame_type is exactly as expected
        :return: Tuple of integers representing frame header and frame type
        :raises McuBootDataAbortError: Target sens Data Abort frame
        :raises McuBootConnectionError: Unexpected frame header or frame type (if specified)
        :raises McuBootConnectionError: When received invalid ACK
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
