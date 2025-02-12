#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Implementation of U-Boot communication interfaces."""

import logging
import os
from tempfile import NamedTemporaryFile
from types import TracebackType
from typing import Optional, Type

from hexdump import restore
from serial import Serial, SerialException

from spsdk.crypto.crc import CrcAlg, from_crc_algorithm
from spsdk.exceptions import SPSDKConnectionError, SPSDKError, SPSDKIndexError
from spsdk.uboot.spsdk_uuu import SPSDKUUU
from spsdk.utils.misc import align, change_endianness, split_data

logger = logging.getLogger(__name__)


class UbootSerial:
    """Class for encapsulation of Uboot CLI interface."""

    LINE_FEED = "\n"
    ENCODING = "ascii"
    READ_ALIGNMENT = 16
    DATA_BYTES_SPLIT = 4
    PROMPT = b"=> "
    INTERRUPT_STRING = "invalid"

    def __init__(
        self,
        port: str,
        timeout: int = 1,
        baudrate: int = 115200,
        crc: bool = True,
        retries: int = 10,
        interrupt_autoboot: bool = True,
    ) -> None:
        """Uboot constructor.

        :param port: TTY port
        :param timeout: timeout in seconds, defaults to 1
        :param baudrate: baudrate, defaults to 115200
        :param crc: True if crc will be calculated, defaults to True
        :param retries: Count of retries for interrupting the autoboot
        :param interrupt_autoboot: If true interrupt autoboot by periodically sending string.
        """
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.is_opened = False
        self.retries = retries
        self.open(interrupt_autoboot)
        self.crc = crc

    def calc_crc(self, data: bytes, address: int, count: int) -> None:
        """Calculate CRC from the data.

        :param data: data to calculate CRC from
        :param address: address from where the data should be calculated
        :param count: count of bytes
        :raises SPSDKError: Invalid CRC of data
        """
        if not self.crc:
            return
        crc_command = f"crc32 {hex(address)} {hex(count)}"
        self.write(crc_command)
        hexdump_str = self.LINE_FEED.join(self.read_output().splitlines())
        if "==>" in hexdump_str:
            hexdump_str += self.LINE_FEED.join(self.read_output().splitlines())
        hexdump_str = hexdump_str.splitlines()[-2][-8:]
        crc_obtained = int("0x" + hexdump_str, base=16)
        logger.debug(f"CRC command:\n{crc_command}\n{crc_obtained}")
        crc_ob = from_crc_algorithm(CrcAlg.CRC32)
        calculated_crc = crc_ob.calculate(data)
        logger.debug(f"Calculated CRC {calculated_crc}")
        if calculated_crc != crc_obtained:
            raise SPSDKError(f"Invalid CRC of data {calculated_crc} != {crc_obtained}")

    def open(self, interrupt_autoboot: bool = True) -> None:
        """Open uboot device.

        :param interrupt_autoboot: interrupt autoboot sequence.
        :raises SPSDKConnectionError: Failed to open serial port
        """
        try:
            self._device = Serial(
                port=self.port,
                timeout=self.timeout,
                write_timeout=self.timeout,
                baudrate=self.baudrate,
            )
        except SerialException as e:
            raise SPSDKConnectionError(f"Failed to open serial port {self.port}") from e
        if interrupt_autoboot:
            self._interrupt_autoboot(self.retries)
        self.is_opened = True

    def __enter__(self) -> "UbootSerial":
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        self.close()

    def is_serial_console_open(self) -> bool:
        """Check if we are already dropped to uboot serial console .

        Function sends an invalid command expecting
        serial console prompt with an error message.

        :return: True if the serial console is open else False
        """
        self.write(self.INTERRUPT_STRING)
        try:
            output = self.read_output()
        except UnicodeDecodeError:
            # Try it once again, with clean buffer
            self.write(self.INTERRUPT_STRING)
            output = self.read_output()
        logger.debug(
            f"Checking if the serial console is open by sending invalid command: {repr(output)}"
        )
        return self.PROMPT.decode(self.ENCODING) in output

    def _interrupt_autoboot(self, retries: int = 10) -> None:
        """Interrupt the uboot booting process.

        Function first checks if we are already in the uboot serial console, if not
        it notifies the user and waits until board reset. Following that it
        interrupts the autoboot by sending input to the console..

        In case of the serial console not being open, we wait for the reset
        :param retries: how many times we should try
        """
        if self.is_serial_console_open():
            return

        logger.info("Waiting for board reset...")

        while not self.is_serial_console_open() and retries > 0:
            retries -= 1

        self.read_output()

    def close(self) -> None:
        """Close uboot device."""
        self._device.close()
        self.is_opened = False

    def read(self, length: int) -> str:
        """Read specified number of characters from uboot CLI.

        :param length: count of read characters
        :return: encoded string
        """
        output = self._device.read(length)
        decoded_output = output.decode(encoding=self.ENCODING)
        logger.debug(f"Uboot READ <- {decoded_output}")
        return decoded_output

    def read_output(self) -> str:
        """Read CLI output until prompt.

        :return: ASCII encoded output
        """
        logger.debug(f"Uboot READ UNTIL <- {self.PROMPT.decode('utf-8')}")
        output = self._device.read_until(expected=self.PROMPT).decode(self.ENCODING)
        return output

    def write(self, data: str, no_exit: bool = False) -> None:
        """Write ASCII decoded data to CLI. Append LINE FEED if not present.

        :param data: ASCII decoded data
        :param no_exit: Do not expect exit code
        """
        logger.debug(f"Uboot WRITE -> {data}")
        if self.LINE_FEED not in data:
            data += self.LINE_FEED
        data_bytes = bytes(data, encoding=self.ENCODING)
        self._device.write(data_bytes)

    def read_memory(self, address: int, count: int) -> bytes:
        """Read memory using the md command. Optionally calculate CRC.

        :param address: Address in memory
        :param count: Count of bytes
        :return: data as bytes
        """
        count = align(count, self.READ_ALIGNMENT)
        md_command = f"md.b {hex(address)} {hex(count)}"
        self.write(md_command)
        hexdump_str = self.LINE_FEED.join(self.read_output().splitlines()[1:-1])
        logger.debug(f"read_memory:\n{md_command}\n{hexdump_str}")
        data = restore(hexdump_str)
        self.calc_crc(data, address, count)

        return data

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory and optionally calculate CRC.

        :param address: Address in memory
        :param data: data as bytes
        """
        start_address = address
        for splitted_data in split_data(data, self.DATA_BYTES_SPLIT):
            mw_command = f"mw.l {hex(address)} {change_endianness(splitted_data).hex()}"
            logger.debug(f"write_memory: {mw_command}")
            self.write(mw_command)
            address += len(splitted_data)
            self.read_output()

        self.calc_crc(data, start_address, len(data))


class UbootFastboot:
    """Class for encapsulation of Uboot Fastboot interface."""

    READ_ALIGNMENT = 16
    LINE_FEED = "\n"
    HEXDUMP_LINE_LENGTH = 75

    def __init__(
        self,
        buffer_address: int,
        buffer_size: int,
        serial_port: Optional[str] = None,
        timeout: int = 5000,
        crc: bool = True,
        usb_path_filter: Optional[str] = None,
        usb_serial_no_filter: Optional[str] = None,
    ):
        """Uboot fastboot interface.

        :param serial_port: Serial port of U-Boot console for opening the fastboot.
        :param buffer_address: Address of buffer in memory for ELE operations
        :param buffer_size: Size of buffer
        :param timeout: Timeout, defaults to 5000
        :param crc: Calculate CRC for frame, defaults to True
        :param usb_path_filter: USB path filter
        :param usb_serial_no_filter: USB serial number filter
        """
        self.timeout = timeout
        self.buffer_address = buffer_address
        self.buffer_size = buffer_size
        self.serial_port = serial_port
        self.is_opened = False
        self.crc = crc
        self.uuu = SPSDKUUU(
            wait_timeout=timeout // 1000,
            wait_next_timeout=timeout // 1000,
            usb_path_filter=usb_path_filter,
            usb_serial_no_filter=usb_serial_no_filter,
        )

    def open(self) -> None:
        """Open interface."""
        if not self.uuu.enable_fastboot_output():
            if not self.serial_port:
                raise SPSDKError(
                    "Fastboot is not open, open the fastboot manually or provide serial port to U-Boot console"
                )
            self.open_fastboot_in_uboot()
            self.uuu.enable_fastboot_output()
        self.is_opened = True

    def close(self) -> None:
        """Close uboot device."""
        self.is_opened = False

    def __enter__(self) -> "UbootFastboot":
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        self.close()

    def open_fastboot_in_uboot(self) -> None:
        """Open fastboot in uboot serial console."""
        if not self.serial_port:
            raise SPSDKError("Serial port must be specified")
        serial = UbootSerial(self.serial_port, timeout=self.timeout // 5000)
        serial.write(f"fastboot -l {hex(self.buffer_address)} -s {hex(self.buffer_size)} usb auto")
        output = serial.read_output()
        if "auto usb" not in output:
            raise SPSDKError("Failed to turn on auto USB mode.")
        serial.close()
        logger.info("Successfully opened fastboot in uboot serial")

    def write(self, command: str, no_exit: bool = False) -> bool:
        """Write uboot command.

        :param command: string command
        :param no_exit: Do not expect exit code (run ACMD).
        :return: Return code from the libuuu
        """
        if no_exit:
            return self.uuu.run_uboot_acmd(command)
        return self.uuu.run_uboot(command)

    def read_output(self) -> str:
        """Decode response from libUUU."""
        return self.uuu.response

    def read_memory(self, address: int, count: int) -> bytes:
        """Read memory using the md command. Optionally calculate CRC.

        :param address: Address in memory
        :param count: Count of bytes
        :return: data as bytes
        """
        count = align(count, self.READ_ALIGNMENT)
        md_command = f"md.b {hex(address)} {hex(count)}"
        self.write(md_command)
        output = self.uuu.response
        # Split the input string into lines and filter to line length of expected hexdump
        filtered_lines = [
            line for line in output.splitlines() if len(line) == self.HEXDUMP_LINE_LENGTH
        ]
        hexdump_str = self.LINE_FEED.join(filtered_lines)
        logger.debug(f"read_memory:\n{md_command!r}\n{hexdump_str}")
        data = restore(hexdump_str)
        if self.crc:
            self.calc_crc(data, address, count)
        return data

    def calc_crc(self, data: bytes, address: int, count: int) -> None:
        """Calculate CRC from the data.

        :param data: data to calculate CRC from
        :param address: address from where the data should be calculated
        :param count: count of bytes
        :raises SPSDKError: Invalid CRC of data
        """
        if not self.crc:
            return
        crc_command = f"crc32 {hex(address)} {hex(count)}"
        self.write(crc_command)
        try:
            hexdump_str = self.uuu.response.splitlines()[0][-8:].strip()
        except IndexError as e:
            raise SPSDKIndexError("Cannot get CRC response") from e
        logger.debug(f"CRC read: {hexdump_str}")
        crc_obtained = int("0x" + hexdump_str, base=16)
        logger.debug(f"CRC command:\n{crc_command!r}\n{crc_obtained!r}")
        crc_ob = from_crc_algorithm(CrcAlg.CRC32)
        calculated_crc = crc_ob.calculate(data)
        logger.debug(f"Calculated CRC {calculated_crc!r}")
        if calculated_crc != crc_obtained:
            raise SPSDKError(f"Invalid CRC of data {calculated_crc} != {crc_obtained}")

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory and optionally calculate CRC.

        :param address: Address in memory
        :param data: data as bytes
        """
        with NamedTemporaryFile(delete=False, mode="w+b") as fp:
            fp.write(data)
            fp.close()
            logger.info(f"Created temporary file {fp.name}")
            self.uuu.uuu.run_cmd(f"FB:DOWNLOAD -f {fp.name}", 0)
            os.remove(fp.name)

        if self.crc:
            self.calc_crc(data, self.buffer_address, len(data))
        command = f"cp.b {hex(self.buffer_address)} {hex(address)} {len(data)}"
        self.write(command)
        if self.crc:
            self.calc_crc(data, address, len(data))

        fp.close()
