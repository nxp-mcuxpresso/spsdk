#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDIO device interface implementation.

This module provides low-level SDIO (Secure Digital Input Output) device
communication interface for SPSDK operations. It implements the SdioDevice
class for handling SDIO protocol communications with NXP MCU devices.
"""

import logging
import os
import time
from io import FileIO
from typing import Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase
from spsdk.utils.misc import Timeout

logger = logging.getLogger(__name__)


class SdioDevice(DeviceBase):
    """SDIO device interface for SPSDK communication.

    This class provides a communication interface for SDIO (Secure Digital Input Output)
    devices, enabling data transfer operations with configurable timeout settings and
    both blocking and non-blocking operation modes.

    :cvar DEFAULT_TIMEOUT: Default timeout value in milliseconds for SDIO operations.
    """

    DEFAULT_TIMEOUT = 2000

    def __init__(
        self,
        path: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the SDIO interface object.

        :param path: Path to the SDIO device, required for connection.
        :param timeout: Communication timeout in seconds, uses DEFAULT_TIMEOUT if not specified.
        :raises SPSDKConnectionError: When the path is None or empty.
        """
        self._opened = False
        # Temporarily use hard code until there is a way to retrieve VID/PID
        self.vid = 0x0471
        self.pid = 0x0209
        self._timeout = timeout or self.DEFAULT_TIMEOUT
        if path is None:
            raise SPSDKConnectionError("No SDIO device path")
        self.path = path
        self.is_blocking = False
        self.device: Optional[FileIO] = None

    @property
    def timeout(self) -> int:
        """Get timeout value for SDIO device operations.

        :return: Timeout value in appropriate units.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set timeout value for the device communication.

        :param value: Timeout value in milliseconds for device operations.
        """
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Check if the SDIO device is currently opened.

        :return: True if device is open, False otherwise.
        """
        return self.device is not None and self._opened

    def open(self) -> None:
        """Open the SDIO device interface.

        Opens the SDIO device file with read/write access and configures it for blocking or
        non-blocking mode based on the interface settings. The device must be available and
        accessible for the operation to succeed.

        :raises McuBootError: If non-blocking mode is not available.
        :raises SPSDKError: If trying to open in non-blocking mode on non-Linux OS.
        :raises SPSDKConnectionError: If no device is available or the device cannot be opened.
        """
        logger.debug("Opening the sdio device.")
        if not self._opened:
            try:
                self.device = open(self.path, "rb+", buffering=0)
                if self.device is None:
                    raise SPSDKConnectionError("No device available")
                if not self.is_blocking:
                    if not hasattr(os, "set_blocking"):
                        raise SPSDKError("Opening in non-blocking mode is available only on Linux")
                    # pylint: disable=no-member     # this is available only on Unix
                    os.set_blocking(self.device.fileno(), False)
                self._opened = True
            except Exception as error:
                raise SPSDKConnectionError(
                    f"Unable to open device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def close(self) -> None:
        """Close the SDIO interface connection.

        Properly closes the SDIO device connection and updates the internal state.
        The method ensures clean disconnection from the device and handles any
        errors that may occur during the closing process.

        :raises SPSDKConnectionError: If no device is available.
        :raises SPSDKConnectionError: If the device cannot be closed properly.
        """
        logger.debug("Closing the sdio Interface.")
        if not self.device:
            raise SPSDKConnectionError("No device available")
        if self._opened:
            try:
                self.device.close()
                self._opened = False
            except Exception as error:
                raise SPSDKConnectionError(
                    f"Unable to close device '{self.path}' VID={self.vid} PID={self.pid}"
                ) from error

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read specified number of bytes from the SDIO device.

        The method uses either blocking or non-blocking read operation based on the device
        configuration. It validates that the device is properly opened before attempting to read.

        :param length: Number of bytes to read from the device.
        :param timeout: Read operation timeout in milliseconds, None for default timeout.
        :return: Data read from the device.
        :raises SPSDKTimeoutError: When read operation times out or no data is received.
        :raises SPSDKConnectionError: When device is not opened for reading.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        _read = self._read_blocking if self.is_blocking else self._read_non_blocking
        data = _read(length=length, timeout=timeout)
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _read_blocking(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read specified number of bytes from device in blocking mode.

        The method reads data from the SDIO device using blocking I/O operation.
        It requires the device to be properly opened before attempting to read.

        :param length: Number of bytes to read from the device.
        :param timeout: Read timeout in seconds (currently not used by implementation).
        :return: Data read from the device as bytes.
        :raises SPSDKConnectionError: When device is not opened for reading.
        :raises SPSDKConnectionError: When reading data from device fails.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug("Reading with blocking mode.")
        try:
            return self.device.read(length)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    def _read_non_blocking(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read specified number of bytes from device in non-blocking mode.

        The method continuously attempts to read data until the requested length is achieved or timeout
        occurs. It handles partial reads and implements retry logic with delays.

        :param length: Number of bytes to read from the device.
        :param timeout: Read timeout in milliseconds, uses default timeout if not specified.
        :return: Data read from the device, may be shorter than requested length on timeout.
        :raises SPSDKConnectionError: When device is not opened or reading fails.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        logger.debug("Reading with non-blocking mode.")
        has_data = 0
        no_data_continuous = 0

        data = bytearray()
        _timeout = Timeout(timeout or self.timeout, "ms")
        while len(data) < length:
            try:
                buf = self.device.read(length)
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e

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
            if _timeout.overflow():
                logger.debug("SDIO interface : read timeout")
                break
        return bytes(data)

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        The method automatically selects blocking or non-blocking mode based on device configuration
        and handles data transmission with proper error handling and logging.

        :param data: Data bytes to send to the device.
        :param timeout: Write operation timeout in seconds, None for default timeout.
        :raises SPSDKConnectionError: Device is not opened or data transmission fails.
        :raises TimeoutError: Write operation exceeds specified timeout.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing.")
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        _write = self._write_blocking if self.is_blocking else self._write_non_blocking
        _write(data=data, timeout=timeout)

    def _write_blocking(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to device in blocking mode.

        :param data: Data to be written to the device.
        :param timeout: Write timeout in seconds (currently not used).
        :raises SPSDKConnectionError: If device is not opened for writing.
        :raises SPSDKConnectionError: If writing data to device fails.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug("Writing in blocking mode")
        try:
            self.device.write(data)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    def _write_non_blocking(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Write data to device in non-blocking mode.

        The method writes data in chunks with timeout handling and sleep intervals
        between write operations to ensure non-blocking behavior.

        :param data: Data bytes to be written to the device.
        :param timeout: Write timeout in milliseconds, uses default timeout if None.
        :raises SPSDKConnectionError: When device is not opened or writing fails.
        :raises SPSDKTimeoutError: When write operation exceeds timeout limit.
        """
        if not self.device or not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug("Writing in non-blocking mode")
        tx_len = len(data)
        _timeout = Timeout(timeout or self.timeout, "ms")
        while tx_len > 0:
            try:
                wr_count = self.device.write(data)
                time.sleep(0.05)
                data = data[wr_count:]
                tx_len -= wr_count
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e
            if _timeout.overflow():
                raise SPSDKTimeoutError()

    def __str__(self) -> str:
        """Return string representation of the SDIO interface.

        The method provides a formatted string containing the vendor ID and product ID
        in hexadecimal format for easy identification of the SDIO device.

        :return: Formatted string with vendor and product IDs in format "(0xVVVV, 0xPPPP)".
        """
        return f"(0x{self.vid:04X}, 0x{self.pid:04X})"

    @classmethod
    def scan(
        cls,
        device_path: str,
        timeout: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected SDIO devices.

        Attempts to connect to the specified SDIO device path to verify availability.
        Creates a device instance if the connection is successful.

        :param device_path: Path string to the SDIO device to scan.
        :param timeout: Read/write timeout in seconds for device operations.
        :return: List containing the SDIO device instance if found, empty list otherwise.
        """
        if device_path is None:
            logger.debug("No sdio path has been defined.")
            devices = []
        try:
            logger.debug(f"Checking path: {device_path}")
            device = cls(path=device_path, timeout=timeout or cls.DEFAULT_TIMEOUT)
            device.open()
            device.close()
            devices = [device] if device else []
        except Exception as e:  # pylint: disable=broad-except
            logger.debug(f"{type(e).__name__}: {e}")
            devices = []
        return devices
