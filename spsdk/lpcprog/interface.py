#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK LPCxxx ISP UART communication interface.

This module provides the communication interface for LPCxxx microcontrollers
using In-System Programming (ISP) protocol over UART connection.
"""

import logging
import time
from typing import Optional

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


class LPCProgInterface:
    """LPCxxx ISP UART communication interface.

    This class provides a communication layer for LPC microcontrollers using the
    In-System Programming (ISP) protocol over UART. It handles synchronization,
    command transmission, and response processing for LPC device programming
    operations.

    :cvar NEW_LINE: Line terminator sequence for UART communication.
    :cvar START_SYNC: Initial synchronization character.
    :cvar SYNC_STRING: Synchronization command string.
    :cvar SYNC_VERIFIED_STRING: Expected synchronization response.
    :cvar RC_SLEEP: Sleep interval for return code operations.
    """

    NEW_LINE = "\r\n"
    START_SYNC = "?"
    SYNC_STRING = f"Synchronized{NEW_LINE}"
    SYNC_VERIFIED_STRING = "OK"

    RC_SLEEP = 0.05

    def __init__(self, device: SerialDevice) -> None:
        """Initialize the LPCProgInterface.

        :param device: Serial device to be used for communication.
        """
        self.device = device
        # echo means that the command is send back to the host
        self.echo = True  # echo is enabled by default
        self.synced = False

    def open(self) -> None:
        """Open the UART interface.

        :raises SPSDKConnectionError: When UART interface cannot be opened.
        """
        try:
            self.device.open()
        except SPSDKError as exc:
            raise SPSDKConnectionError(f"Cannot open UART interface: {exc}") from exc

    def close(self) -> None:
        """Close the UART interface.

        :raises SPSDKConnectionError: In any case of fail of UART close operation.
        """
        try:
            self.device.close()
        except SPSDKError as exc:
            raise SPSDKConnectionError(f"Cannot close UART interface: {exc}") from exc

    def read_line(self, decode: bool = True) -> str:
        """Read line from the device.

        The method reads a line of data from the connected device and optionally decodes it as UTF-8.
        If decoding fails, an empty string is returned instead of raising an exception.

        :param decode: Whether to decode the data as UTF-8 string, defaults to True
        :raises SPSDKError: When read operation fails
        :raises SPSDKTimeoutError: When no data is received (timeout)
        :return: Data read from the device as string (decoded or hex format)
        """
        try:
            data = self.device._device.readline()
            logger.debug(f"<-READ DATA({len(data)}):  <{' '.join(f'{b:02x}' for b in data)}>")
            if decode:
                data = data.decode("utf-8")
            else:
                data = " ".join(f"{b:02x}" for b in data)
        except UnicodeDecodeError:
            logger.debug("Cannot decode response")
            return ""
        except Exception as e:
            raise SPSDKError(str(e)) from e
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<-READ LINE: {data}")
        return data

    def read_all(self) -> bytes:
        """Read all available data from the device.

        This method retrieves all pending data from the connected device buffer.
        If no data is available, a timeout error is raised.

        :raises SPSDKError: When read operation fails
        :raises SPSDKTimeoutError: When no data is available to read
        :return: Data read from the device
        """
        try:
            data = self.device._device.read_all()
        except Exception as e:
            raise SPSDKError(str(e)) from e
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<-READ ALL:  <{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _read(self, length: int) -> bytes:
        """Read specified number of bytes from device.

        The method reads data from the underlying device and provides debug logging
        of the received data in hexadecimal format.

        :param length: Number of bytes to read from the device.
        :raises SPSDKTimeoutError: When no data is received from device.
        :raises SPSDKError: When reading data from device fails.
        :return: Data read from the device.
        """
        try:
            data = self.device._device.read(length)
        except Exception as e:
            raise SPSDKError(str(e)) from e
        if not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<-READ DATA({len(data)}):  <{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send to the device
        :raises SPSDKError: When sending the data fails
        """
        logger.debug(f"->WRITE DATA({len(data)}): [{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device._device.write(data)
        except Exception as e:
            raise SPSDKError(str(e)) from e

    def write_string(self, data: str) -> None:
        """Write string to serial device.

        :param data: String data to be written to the serial device.
        :raises SPSDKError: If writing to the serial device fails.
        """
        logger.debug(f"->WRITE STRING: {data}")
        self.write(bytes(data, "utf-8"))

    def _get_return_code(self) -> int:
        """Get return code from the device.

        Reads a line from the device and parses it as an integer return code. If echo is enabled,
        the method discards the first echoed line and reads the actual response.

        :raises SPSDKConnectionError: Timeout while waiting for response or cannot decode response
                                     as return code.
        :return: Return code from the device as integer.
        """
        try:
            resp = self.read_line()
            if self.echo:  # discard echo
                resp = self.read_line()
        except TimeoutError as e:
            self.write(bytes(self.NEW_LINE, encoding="utf-8"))
            raise SPSDKConnectionError("Timeout while waiting for response") from e
        try:
            rc = int(resp.strip())
        except ValueError as exc:
            raise SPSDKConnectionError(f"Cannot decode {resp} as RC") from exc
        return rc

    def send_command(self, command: str, expect_rc: bool = True) -> Optional[int]:
        """Send command to the device and optionally wait for return code.

        Writes the specified command string to the device with a newline terminator.
        If expect_rc is True, waits for and retrieves the return code from the device.

        :param command: Command string to send to the device.
        :param expect_rc: Whether to wait for and return the device return code.
        :return: Return code from device if expect_rc is True, None otherwise.
        """
        self.write_string(command + self.NEW_LINE)
        if expect_rc:
            time.sleep(self.RC_SLEEP)
            return self._get_return_code()
        return None

    def clear_serial(self) -> None:
        """Clear serial communication buffers.

        This method flushes all pending data in the serial device buffers including
        input and output buffers to ensure clean communication state.

        :raises SPSDKError: If buffer clearing operation fails.
        """
        self.device._device.flush()
        self.device._device.reset_input_buffer()
        self.device._device.reset_output_buffer()

    def sync_connection(self, frequency: int, retries: int = 10) -> None:
        """Synchronize connection with the target device.

        Establishes communication by exchanging synchronization messages and setting
        the crystal frequency. The method implements a retry mechanism to handle
        communication failures during the synchronization process.

        1. Send ? to get baud rate
        2. Receive "Synchronized" message
        3. Send "Synchronized" message
        4. Receive "OK" message

        :param frequency: Frequency of the crystal in Hz.
        :param retries: Number of synchronization attempts, defaults to 10.
        :raises SPSDKError: Invalid retries parameter (must be positive).
        :raises SPSDKConnectionError: Synchronization failed or invalid response.
        """
        if self.synced:
            return

        if retries <= 0:
            raise SPSDKError("Retries for sync must be positive number")

        while retries > 0:
            self.clear_serial()
            # send ?
            self.write_string(self.START_SYNC)
            time.sleep(0.1)
            # receive "Synchronized" response
            if self.SYNC_STRING not in self.read_line():
                retries -= 1
                logger.warning(f"Did not receive 'Synchronized' response, attempts left: {retries}")
                continue
            else:
                logger.debug("Received synchronized response")
                # send "Synchronized" message
                self.write_string(self.SYNC_STRING + "\r\n")
                self.read_line()
                self.write_string(f"{frequency}\r\n")
                if self.SYNC_VERIFIED_STRING not in self.read_line():
                    raise SPSDKConnectionError("Did not receive 'OK' response")
                logger.info("Synchronized")
                self.synced = True
                return
        if not self.synced:
            raise SPSDKConnectionError("Cannot synchronize")
