#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK U-Boot communication interface implementation.

This module provides communication interfaces for interacting with U-Boot bootloader
through different protocols including serial and fastboot connections.
"""

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
    """SPSDK U-Boot Serial Communication Interface.

    This class provides a serial communication interface for interacting with U-Boot
    bootloader through CLI commands. It handles serial port management, autoboot
    interruption, command execution, and data validation with CRC checking.

    :cvar LINE_FEED: Line feed character for command formatting.
    :cvar ENCODING: Character encoding for serial communication.
    :cvar READ_ALIGNMENT: Memory alignment for read operations.
    :cvar DATA_BYTES_SPLIT: Byte grouping for data processing.
    :cvar PROMPT: U-Boot command prompt identifier.
    :cvar INTERRUPT_STRING: String used to interrupt autoboot sequence.
    """

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
        retries: int = 5,
        interrupt_autoboot: bool = True,
    ) -> None:
        """Initialize U-Boot communication interface.

        Establishes serial communication with U-Boot bootloader, optionally interrupting
        the autoboot sequence to gain control of the boot process.

        :param port: Serial port identifier (e.g., 'COM1' on Windows, '/dev/ttyUSB0' on Linux).
        :param timeout: Communication timeout in seconds, defaults to 1.
        :param baudrate: Serial communication baud rate, defaults to 115200.
        :param crc: Enable CRC calculation for data integrity, defaults to True.
        :param retries: Number of attempts to interrupt autoboot sequence, defaults to 5.
        :param interrupt_autoboot: Enable automatic interruption of U-Boot autoboot sequence,
            defaults to True.
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

        Executes CRC32 calculation command on the target device and validates the result
        against locally calculated CRC. If CRC validation is disabled, the method returns
        without performing any checks.

        :param data: Data to calculate CRC from.
        :param address: Memory address from where the data should be calculated.
        :param count: Number of bytes to include in CRC calculation.
        :raises SPSDKError: Invalid CRC of data when calculated and obtained CRC values
            don't match.
        """
        try:
            if not self.crc:
                return
            crc_command = f"crc32 {hex(address)} {hex(count)}"
            self.write(crc_command)
            hexdump_str = self.LINE_FEED.join(self.read_output().splitlines())
            if "==>" in hexdump_str:
                hexdump_str += self.LINE_FEED.join(self.read_output().splitlines())
            hexdump_str = hexdump_str.splitlines()[-2][-8:]
            crc_obtained = int("0x" + hexdump_str, base=16)
        except Exception as e:
            logger.info(f"CRC calculation failed: {e}")
            return
        logger.debug(f"CRC command:\n{crc_command}\n{crc_obtained}")
        crc_ob = from_crc_algorithm(CrcAlg.CRC32)
        calculated_crc = crc_ob.calculate(data)
        logger.debug(f"Calculated CRC {calculated_crc}")
        if calculated_crc != crc_obtained:
            raise SPSDKError(f"Invalid CRC of data {calculated_crc} != {crc_obtained}")

    def open(self, interrupt_autoboot: bool = True) -> None:
        """Open uboot device.

        Establishes serial connection to the U-Boot device and optionally interrupts the autoboot sequence
        to gain control of the U-Boot command prompt.

        :param interrupt_autoboot: Whether to interrupt the autoboot sequence after opening connection.
        :raises SPSDKConnectionError: Failed to open serial port.
        """
        try:
            self._device = Serial(
                port=self.port,
                timeout=self.timeout // 1000,
                write_timeout=self.timeout // 1000,
                baudrate=self.baudrate,
            )
        except SerialException as e:
            raise SPSDKConnectionError(f"Failed to open serial port {self.port}") from e
        if interrupt_autoboot:
            self._interrupt_autoboot(self.retries)
        self.is_opened = True

    def __enter__(self) -> "UbootSerial":
        """Enter the runtime context for UbootSerial.

        This method is called when entering a 'with' statement context manager,
        automatically opening the U-Boot serial connection.

        :return: The UbootSerial instance for use within the context.
        """
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Exit the context manager and close the U-Boot connection.

        This method is called automatically when exiting a 'with' statement block.
        It ensures proper cleanup by closing the U-Boot connection regardless of
        whether an exception occurred within the context.

        :param exception_type: The type of exception that caused the context to exit,
            or None if no exception occurred.
        :param exception_value: The exception instance that caused the context to exit,
            or None if no exception occurred.
        :param traceback: The traceback object associated with the exception,
            or None if no exception occurred.
        """
        self.close()

    def is_serial_console_open(self) -> bool:
        """Check if we are already dropped to uboot serial console.

        Function sends an invalid command expecting serial console prompt with an error message.
        If a UnicodeDecodeError occurs during the first attempt, the function retries once more
        with a clean buffer.

        :return: True if the serial console is open, False otherwise.
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
        """Interrupt the U-Boot autoboot process.

        Checks if already in the U-Boot serial console. If not, waits for board reset and
        interrupts the autoboot sequence by monitoring the serial console availability.
        The method will retry the specified number of times before failing.

        :param retries: Number of retry attempts to interrupt autoboot.
        :raises SPSDKConnectionError: If unable to interrupt autoboot after all retries.
        """
        if self.is_serial_console_open():
            return

        logger.info("Waiting for board reset...")

        while not self.is_serial_console_open() and retries > 0:
            retries -= 1

        if not self.is_serial_console_open():
            raise SPSDKConnectionError(
                f"Failed to interrupt autoboot after {10 - retries} attempts. "
                "Please ensure the board is reset and autoboot can be interrupted."
            )

        self.read_output()

    def close(self) -> None:
        """Close the U-Boot device connection.

        This method closes the underlying device connection and updates the connection status.
        The device will no longer be available for communication after calling this method.
        """
        self._device.close()
        self.is_opened = False

    def read(self, length: int) -> str:
        """Read specified number of characters from U-Boot CLI.

        The method reads raw data from the underlying device interface and decodes it
        using the configured encoding format.

        :param length: Number of characters to read from the CLI interface.
        :return: Decoded string output from U-Boot CLI.
        """
        output = self._device.read(length)
        decoded_output = output.decode(encoding=self.ENCODING)
        logger.debug(f"Uboot READ <- {decoded_output}")
        return decoded_output

    def read_output(self) -> str:
        """Read CLI output until prompt.

        The method reads data from the device until the U-Boot prompt is encountered
        and returns the decoded output.

        :return: ASCII encoded output from the CLI
        """
        logger.debug(f"Uboot READ UNTIL <- {self.PROMPT.decode('utf-8')}")
        output = self._device.read_until(expected=self.PROMPT).decode(self.ENCODING)
        return output

    def write(self, data: str, no_exit: bool = False) -> None:
        """Write ASCII decoded data to CLI.

        Appends LINE FEED character if not present in the data.

        :param data: ASCII decoded data to write to the CLI interface.
        :param no_exit: Flag to indicate whether to expect exit code or not.
        """
        logger.debug(f"Uboot WRITE -> {data}")
        if self.LINE_FEED not in data:
            data += self.LINE_FEED
        data_bytes = bytes(data, encoding=self.ENCODING)
        self._device.write(data_bytes)

    def read_memory(self, address: int, count: int) -> bytes:
        """Read memory using the md command.

        The method reads memory data from specified address and count of bytes using U-Boot's
        md command. It automatically aligns the count to READ_ALIGNMENT and optionally
        calculates CRC for verification.

        :param address: Memory address to read from.
        :param count: Number of bytes to read from memory.
        :return: Memory data as bytes.
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
        """Write memory data to specified address and calculate CRC.

        The method splits the data into chunks and writes each chunk to memory using
        U-Boot memory write commands. After writing all data, it calculates and verifies
        the CRC of the written data.

        :param address: Target memory address where data will be written.
        :param data: Binary data to write to memory.
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
    """U-Boot Fastboot Interface Manager.

    This class provides a comprehensive interface for communicating with U-Boot's
    fastboot protocol, enabling memory operations, data transfer, and device
    management through both USB and serial connections.

    :cvar READ_ALIGNMENT: Memory read alignment requirement in bytes.
    :cvar LINE_FEED: Line feed character for console communication.
    :cvar HEXDUMP_LINE_LENGTH: Maximum length for hexadecimal dump output lines.
    """

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
        """Initialize U-Boot fastboot interface.

        The interface provides communication with U-Boot fastboot mode using UUU protocol
        for secure provisioning operations with ELE (EdgeLock Enclave).

        :param buffer_address: Address of buffer in memory for ELE operations.
        :param buffer_size: Size of buffer in bytes.
        :param serial_port: Serial port of U-Boot console for opening the fastboot.
        :param timeout: Communication timeout in milliseconds, defaults to 5000.
        :param crc: Calculate CRC for frame validation, defaults to True.
        :param usb_path_filter: USB path filter for device selection.
        :param usb_serial_no_filter: USB serial number filter for device selection.
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
        """Open the U-Boot interface for communication.

        This method establishes communication with the U-Boot interface by enabling
        fastboot output. If fastboot is not already available, it attempts to open
        fastboot through the U-Boot console using the provided serial port.

        :raises SPSDKError: When fastboot is not open and no serial port is provided
            for U-Boot console access.
        """
        if not self.uuu.enable_fastboot_output():
            if not self.serial_port:
                raise SPSDKError(
                    "Fastboot is not open, open the fastboot manually or provide serial port to U-Boot console"
                )
            self.open_fastboot_in_uboot()
            self.uuu.enable_fastboot_output()
        self.is_opened = True

    def close(self) -> None:
        """Close the U-Boot device connection.

        This method properly closes the connection to the U-Boot device and sets the device state
        to closed. After calling this method, the device will no longer be available for
        communication until reopened.
        """
        self.is_opened = False

    def __enter__(self) -> "UbootFastboot":
        """Enter the runtime context for UbootFastboot.

        Opens the connection and returns the instance for use in a with statement.

        :return: The UbootFastboot instance for context management.
        """
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Clean up resources and close the U-Boot interface.

        This method is called automatically when exiting a context manager (with statement).
        It ensures proper cleanup of any open connections or resources.

        :param exception_type: Type of exception that caused the context to exit, if any.
        :param exception_value: Exception instance that caused the context to exit, if any.
        :param traceback: Traceback object associated with the exception, if any.
        """
        self.close()

    def open_fastboot_in_uboot(self) -> None:
        """Open fastboot in uboot serial console.

        Establishes a serial connection to the uboot console and executes the fastboot command
        to enable USB fastboot mode with specified buffer address and size.

        :raises SPSDKError: Serial port is not specified or fastboot command failed.
        """
        if not self.serial_port:
            raise SPSDKError("Serial port must be specified")
        serial = UbootSerial(self.serial_port, timeout=self.timeout // 5000)
        serial.write(f"fastboot -l {hex(self.buffer_address)} -s {hex(self.buffer_size)} usb 0")
        output = serial.read_output()
        if "Error" in output:
            raise SPSDKError("Failed to turn on auto USB mode.")
        serial.close()
        logger.info("Successfully opened fastboot in uboot serial")

    def write(self, command: str, no_exit: bool = False) -> bool:
        """Write U-Boot command to the target device.

        The method executes U-Boot commands through libuuu interface, with option to run
        asynchronous commands that don't wait for exit code.

        :param command: U-Boot command string to execute.
        :param no_exit: If True, run as asynchronous command (ACMD) without waiting for exit code.
        :return: True if command executed successfully, False otherwise.
        """
        if no_exit:
            return self.uuu.run_uboot_acmd(command)
        return self.uuu.run_uboot(command)

    def read_output(self) -> str:
        """Get response from libUUU.

        Read and decode the response string that was received from the libUUU library
        after executing U-Boot commands.

        :return: Decoded response string from libUUU.
        """
        return self.uuu.response

    def read_memory(self, address: int, count: int) -> bytes:
        """Read memory using the md command.

        The method reads specified number of bytes from memory at given address using U-Boot's
        md.b command. The count is automatically aligned to READ_ALIGNMENT. Optionally calculates
        CRC if enabled.

        :param address: Memory address to read from.
        :param count: Number of bytes to read.
        :return: Read memory data as bytes.
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

        Validates data integrity by computing CRC32 checksum and comparing it with
        the value obtained from the target device at the specified memory address.

        :param data: Data bytes to calculate CRC from.
        :param address: Memory address from where the data should be calculated.
        :param count: Number of bytes to include in CRC calculation.
        :raises SPSDKError: Invalid CRC of data when checksums don't match.
        :raises SPSDKIndexError: Cannot get CRC response from device.
        """
        try:
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
        except Exception as e:
            logger.info(f"CRC calculation failed: {e}")
            return
        logger.debug(f"CRC command:\n{crc_command!r}\n{crc_obtained!r}")
        crc_ob = from_crc_algorithm(CrcAlg.CRC32)
        calculated_crc = crc_ob.calculate(data)
        logger.debug(f"Calculated CRC {calculated_crc!r}")
        if calculated_crc != crc_obtained:
            raise SPSDKError(f"Invalid CRC of data {calculated_crc} != {crc_obtained}")

    def write_memory(self, address: int, data: bytes) -> None:
        """Write memory data to specified address with optional CRC verification.

        The method writes data to memory by first downloading it to a buffer address,
        then copying it to the target address. CRC calculation can be performed
        before and after the copy operation if enabled.

        :param address: Target memory address where data will be written.
        :param data: Binary data to write to memory.
        :raises SPSDKError: If memory write operation fails.
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

    def verify_connection(self, timeout: int = 1) -> bool:
        """Verify if the fastboot connection is active.

        The method checks if the connection is opened and uses UUU instance to verify
        the fastboot connection with specified timeout.

        :param timeout: Timeout in seconds for verification, defaults to 1 second.
        :return: True if connection is active, False otherwise.
        """
        if not self.is_opened:
            return False

        try:
            # Use the UUU instance to verify with short timeout
            return self.uuu.verify_fastboot_connection(timeout)
        except Exception as e:
            logger.debug(f"Connection verification failed: {e}")
            return False
