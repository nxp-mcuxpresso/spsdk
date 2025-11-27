#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK serial device interface implementation.

This module provides SerialDevice class for communication with devices
over serial/UART interfaces, including device discovery and connection
management functionality.
"""

import logging
from typing import Optional

from serial import Serial, SerialTimeoutException
from serial.tools.list_ports import comports
from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError, SPSDKPermissionError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase

logger = logging.getLogger(__name__)


class SerialDevice(DeviceBase):
    """SPSDK Serial Device Interface.

    This class provides a unified interface for serial communication with NXP MCU devices
    over UART connections. It handles serial port configuration, connection management,
    and data transfer operations with proper timeout and error handling.

    :cvar DEFAULT_BAUDRATE: Default serial communication speed (115200 bps).
    :cvar DEFAULT_TIMEOUT: Default read/write timeout in milliseconds (5000 ms).
    """

    DEFAULT_BAUDRATE = 115200
    DEFAULT_TIMEOUT = 5000

    def __init__(
        self,
        port: Optional[str] = None,
        timeout: Optional[int] = None,
        baudrate: Optional[int] = None,
    ):
        """Initialize the UART interface.

        :param port: Name of the serial port, defaults to None
        :param timeout: Read/write timeout in milliseconds, defaults to 1000
        :param baudrate: Speed of the UART interface, defaults to 115200
        :raises SPSDKConnectionError: When there is no port available
        :raises SPSDKPermissionError: When the permission is denied
        """
        super().__init__()
        self._timeout = timeout or self.DEFAULT_TIMEOUT
        try:
            timeout_s = self._timeout / 1000
            self._device = Serial(
                port=port,
                timeout=timeout_s,
                write_timeout=timeout_s,
                baudrate=baudrate or self.DEFAULT_BAUDRATE,
            )
        except Exception as e:
            if "PermissionError" in str(e):
                raise SPSDKPermissionError(f"Could not open port '{port}'. Access denied.") from e
            raise SPSDKConnectionError(str(e)) from e

    @property
    def timeout(self) -> int:
        """Get timeout value for serial device communication.

        :return: Timeout value in seconds for serial operations.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set timeout value for serial device communication.

        Configures both read and write timeout values for the underlying serial device.
        The timeout value is converted from milliseconds to seconds for the device.

        :param value: Timeout value in milliseconds.
        """
        self._timeout = value
        self._device.timeout = value / 1000
        self._device.write_timeout = value / 1000

    @property
    def is_opened(self) -> bool:
        """Check if the serial device is currently open.

        :return: True if device is open, False otherwise.
        """
        return self._device.is_open

    def open(self) -> None:
        """Open the UART interface.

        :raises SPSDKPermissionError: When the permission is denied
        :raises SPSDKConnectionError: When opening device fails
        """
        if not self.is_opened:
            try:
                self._device.open()
            except Exception as e:
                self.close()
                if "PermissionError" in str(e):
                    raise SPSDKPermissionError(str(e)) from e
                raise SPSDKConnectionError(str(e)) from e

    def close(self) -> None:
        """Close the UART interface.

        The method safely closes the serial device connection by first clearing
        input and output buffers, then closing the device handle.

        :raises SPSDKConnectionError: When closing device fails.
        """
        if self.is_opened:
            try:
                self._device.reset_input_buffer()
                self._device.reset_output_buffer()
                self._device.close()
            except Exception as e:
                raise SPSDKConnectionError(str(e)) from e

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the serial device.

        Reads the specified number of bytes from the connected serial device.
        The method will raise an exception if the device is not opened or if
        no data is available to read.

        :param length: Number of bytes to read from the device.
        :param timeout: Read timeout in seconds, if None uses default timeout.
        :return: Data read from the device.
        :raises SPSDKConnectionError: When device is not opened or reading fails.
        :raises SPSDKTimeoutError: When no data is available to read (timeout).
        """
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        try:
            data = self._device.read(length)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        The method clears input/output buffers before sending data and flushes the output
        to ensure reliable transmission.

        :param data: Data bytes to send to the device.
        :param timeout: Write timeout in seconds (currently not used in implementation).
        :raises SPSDKTimeoutError: When sending of data times out.
        :raises SPSDKConnectionError: When device is not opened or send operation fails.
        """
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self._device.reset_input_buffer()
            self._device.reset_output_buffer()
            self._device.write(data)
            self._device.flush()
        except SerialTimeoutException as e:
            raise SPSDKTimeoutError(
                f"Write timeout error. The timeout is set to {self._device.write_timeout} s. Consider increasing it."
            ) from e
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    def __str__(self) -> str:
        """Return string representation of the UART interface.

        :return: Port name of the UART interface.
        :raises SPSDKConnectionError: When information cannot be collected from device.
        """
        try:
            return self._device.port
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e

    @classmethod
    def scan(
        cls,
        port: Optional[str] = None,
        baudrate: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected serial ports for responding devices.

        Returns list of serial ports with devices that respond to PING command.
        If 'port' is specified, only that serial port is checked.
        If no devices are found, return an empty list.

        :param port: Name of preferred serial port, defaults to None.
        :param baudrate: Speed of the UART interface, defaults to 56700.
        :param timeout: Timeout in milliseconds, defaults to 5000.
        :return: List of interfaces responding to the PING command.
        """
        baudrate = baudrate or cls.DEFAULT_BAUDRATE
        timeout = timeout or 5000
        if port:
            device = cls._check_port(port, baudrate, timeout)
            devices = [device] if device else []
        else:
            all_ports = [
                cls._check_port(comport.device, baudrate, timeout)
                for comport in comports(include_links=True)
            ]
            devices = list(filter(None, all_ports))
        return devices

    @classmethod
    def _check_port(cls, port: str, baudrate: int, timeout: int) -> Optional[Self]:
        """Check if device on serial port responds to connection attempt.

        The method tries to establish connection with a device on the specified serial port
        by opening and immediately closing the connection to verify accessibility.

        :param port: Name of the serial port to check.
        :param baudrate: Speed of the UART interface in bits per second.
        :param timeout: Connection timeout in milliseconds.
        :return: Device instance if connection successful, None if connection fails or port inaccessible.
        """
        try:
            logger.debug(f"Checking port: {port}, baudrate: {baudrate}, timeout: {timeout}")
            device = cls(port=port, baudrate=baudrate, timeout=timeout)
            device.open()
            device.close()
            return device
        except SPSDKPermissionError as e:
            logger.warning(f"{type(e).__name__}: {e}")
            return None
        except Exception as e:  # pylint: disable=broad-except
            logger.info(f"{type(e).__name__}: {e}")
            return None
