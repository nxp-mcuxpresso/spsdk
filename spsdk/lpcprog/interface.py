#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""LPCxxx ISP UART communication interface."""

import logging
import time
from typing import Optional

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.serial_device import SerialDevice

logger = logging.getLogger(__name__)


class LPCProgInterface:
    """LPCxxx ISP UART communication interface."""

    NEW_LINE = "\r\n"
    START_SYNC = "?"
    SYNC_STRING = f"Synchronized{NEW_LINE}"
    SYNC_VERIFIED_STRING = "OK"

    RC_SLEEP = 0.05

    def __init__(self, device: SerialDevice) -> None:
        """Initialize the LPCProgInterface.

        :param device: Serial device
        """
        self.device = device
        # echo means that the command is send back to the host
        self.echo = True  # echo is enabled by default
        self.synced = False

    def open(self) -> None:
        """Open the UART interface.

        :raises SPSDKError: In any case of fail of UART open operation.
        """
        try:
            self.device.open()
        except SPSDKError as exc:
            raise SPSDKConnectionError(f"Cannot open UART interface: {exc}") from exc

    def close(self) -> None:
        """Close the UART interface.

        :raises SPSDKError: In any case of fail of UART close operation.
        """
        try:
            self.device.close()
        except SPSDKError as exc:
            raise SPSDKConnectionError(f"Cannot close UART interface: {exc}") from exc

    def read_line(self, decode: bool = True) -> str:
        """Read line from the device.

        :raises SPSDKError: When read fails
        :raises TimeoutError: Time-out
        :return: Data read from the device
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
        """Read all data from the device.

        :raises SPSDKError: When read fails
        :raises TimeoutError: Time-out
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
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises TimeoutError: Time-out
        :raises SPSDKError: When reading data from device fails
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

        :param data: Data to send
        :raises SPSDKError: When sending the data fails
        """
        logger.debug(f"->WRITE DATA({len(data)}): [{' '.join(f'{b:02x}' for b in data)}]")
        try:
            self.device._device.write(data)
        except Exception as e:
            raise SPSDKError(str(e)) from e

    def write_string(self, data: str) -> None:
        """Write string to serial device.

        :param data: string data
        """
        logger.debug(f"->WRITE STRING: {data}")
        self.write(bytes(data, "utf-8"))

    def _get_return_code(self) -> int:
        """Get return code from the device."""
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
        """Writes command."""
        self.write_string(command + self.NEW_LINE)
        if expect_rc:
            time.sleep(self.RC_SLEEP)
            return self._get_return_code()
        return None

    def clear_serial(self) -> None:
        """Flush buffers."""
        self.device._device.flush()
        self.device._device.reset_input_buffer()
        self.device._device.reset_output_buffer()

    def sync_connection(self, frequency: int, retries: int = 10) -> None:
        """Synchronize connection.

        :param frequency: Frequency of the crystal
        :param retries: Number of retries for synchronization (10 default)

        1. Send ? to get baud rate
        2. Receive "Synchronized" message
        3. Send "Synchronized" message
        4. Receive "OK" message
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
