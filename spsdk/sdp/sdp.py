#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Serial Download Protocol (SDP) communication implementation.

This module provides the SDP class for communicating with NXP MCUs using
the Serial Download Protocol, enabling device programming and debugging
operations through various interfaces.
"""

import logging
import math
from typing import Any, Optional

from spsdk.sdp.commands import CmdPacket, CommandTag, ResponseValue
from spsdk.sdp.error_codes import StatusCode
from spsdk.sdp.exceptions import SdpCommandError, SdpConnectionError, SdpError
from spsdk.sdp.interfaces import SDPDeviceTypes

logger = logging.getLogger(__name__)


########################################################################################################################
# Serial Downloader Protocol (SDP) Class
########################################################################################################################
class SDP:
    """Serial Downloader Protocol interface for i.MX devices.

    This class provides a high-level interface for communicating with i.MX devices
    using the Serial Downloader Protocol (SDP). It manages device connections,
    command execution, and status tracking for secure provisioning operations.
    """

    @property
    def status_code(self) -> StatusCode:
        """Get status code from SDP.

        :return: Current status code of the SDP communication.
        """
        return self._status_code

    @property
    def hab_status(self) -> int:
        """Get the response value from HAB.

        :return: HAB status response value.
        """
        return self._hab_status

    @property
    def cmd_status(self) -> int:
        """Get the response value from the command.

        :return: The status code from the last executed command.
        """
        return self._cmd_status

    @property
    def is_opened(self) -> bool:
        """Check interface connection status.

        :return: True if device is open, False if it's closed.
        """
        return self._interface.is_opened

    def __init__(self, interface: SDPDeviceTypes, cmd_exception: bool = False) -> None:
        """Initialize the SDP object.

        :param interface: Interface to a device
        :param cmd_exception: True if commands should raise in exception, defaults to False
        """
        self._hab_status = 0
        self._cmd_exception = cmd_exception
        self._status_code = StatusCode.SUCCESS
        self._cmd_status = 0
        self._interface = interface

    def __enter__(self) -> "SDP":
        """Enter the runtime context of the SDP object.

        This method is used as part of the context manager protocol to initialize
        the SDP connection when entering a 'with' statement block.

        :return: The SDP instance itself for use within the context block.
        """
        self.open()
        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        """Context manager exit method for SDP interface.

        Properly closes the SDP connection and cleans up resources when exiting
        the context manager.

        :param args: Variable length argument list (unused).
        :param kwargs: Arbitrary keyword arguments (unused).
        """
        self.close()

    def open(self) -> None:
        """Connect to i.MX device.

        Establishes connection to the i.MX device using the configured interface.

        :raises SPSDKConnectionError: If the connection to the device fails.
        """
        logger.info(f"Connect: {str(self._interface)}")
        self._interface.open()

    def close(self) -> None:
        """Close the connection to i.MX device.

        This method properly disconnects the communication interface with the i.MX device
        and releases any associated resources.
        """
        self._interface.close()

    def _process_cmd(self, cmd_packet: CmdPacket) -> bool:
        """Process Command Packet.

        Sends a command packet to the device interface and processes the response.
        Updates internal status codes and HAB status based on the response.

        :param cmd_packet: Command packet object to be sent to the device.
        :return: True if command was processed successfully, False otherwise.
        :raises SdpConnectionError: If device is disconnected or timeout/connection error occurs.
        """
        if not self.is_opened:
            logger.info("RX-CMD: Device Disconnected")
            raise SdpConnectionError("Device Disconnected !")

        logger.debug(f"TX-PACKET: {str(cmd_packet)}")
        self._status_code = StatusCode.SUCCESS

        try:
            self._interface.write_command(cmd_packet)
            response = self._interface.read()
        except Exception as exc:
            logger.debug(exc)
            logger.info("RX-CMD: Timeout Error")
            raise SdpConnectionError("Timeout Error") from exc

        logger.info(f"RX-PACKET: {str(response)}")
        if response.hab:
            if response.value not in [ResponseValue.UNLOCKED.tag, ResponseValue.LOCKED.tag]:
                return False

            self._hab_status = response.value
            if response.value != ResponseValue.UNLOCKED:
                self._status_code = StatusCode.HAB_IS_LOCKED

        return True

    def _read_status(self) -> int:
        """Read status value from the SDP interface.

        The method reads the status response from the connected device interface
        and logs the received packet for debugging purposes.

        :return: Status code value from the device response.
        :raises SdpConnectionError: When timeout occurs during interface read operation.
        """
        try:
            response = self._interface.read()
            logger.info(f"RX-PACKET: {str(response)}")
        except Exception as exc:
            logger.info("RX-CMD: Timeout Error")
            raise SdpConnectionError("Timeout Error") from exc

        return response.value

    def _read_data(self, length: int) -> Optional[bytes]:
        """Read data from device.

        The method reads data in chunks with maximum size of 64 bytes and handles HAB status
        responses. It continues reading until the requested length is obtained or an error occurs.

        :param length: Count of bytes to read from device.
        :return: Bytes read from device, truncated to requested length if necessary.
        :raises SdpConnectionError: Timeout or connection error during read operation.
        """
        max_length = 64
        data = b""
        remaining = length - len(data)
        while remaining > 0:
            try:
                self._interface.expect_status = False
                response = self._interface.read(min(remaining, max_length))
            except Exception as exc:
                logger.info("RX-CMD: Timeout Error")
                raise SdpConnectionError("Timeout Error") from exc

            if not response.hab:
                data += response.raw_data
            else:
                logger.debug(f"RX-DATA: {str(response)}")
                self._hab_status = response.value
                if response.value == ResponseValue.LOCKED:
                    self._status_code = StatusCode.HAB_IS_LOCKED
            remaining = length - len(data)
        return data[:length] if len(data) > length else data

    def _send_data(self, cmd_packet: CmdPacket, data: bytes) -> bool:
        """Send data to target device.

        Sends a command packet followed by data payload to the target device through the SDP interface.
        The method handles the complete communication flow including sending the command, transmitting
        data, and reading back HAB status and command response.

        :param cmd_packet: Command packet object containing the command to execute.
        :param data: Byte array with data payload to send to the target device.
        :return: True if the write operation is successful, False otherwise.
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True.
        :raises SdpConnectionError: If device is disconnected, timeout or connection error occurs.
        """
        if not self.is_opened:
            logger.info("TX-DATA: Device Disconnected")
            raise SdpConnectionError("Device Disconnected !")

        logger.debug(f"TX-PACKET: {str(cmd_packet)}")
        self._status_code = StatusCode.SUCCESS
        ret_val = True

        try:
            # Send Command
            self._interface.write_command(cmd_packet)

            # Send Data
            self._interface.write_data(data)

            # Read HAB state (locked / unlocked)
            hab_response = self._interface.read()
            logger.debug(f"RX-DATA: {str(hab_response)}")
            self._hab_status = hab_response.value
            if hab_response.value != ResponseValue.UNLOCKED:
                self._hab_status = StatusCode.HAB_IS_LOCKED.tag

            # Read Command Status
            cmd_response = self._interface.read()
            logger.debug(f"RX-DATA: {str(cmd_response)}")
            self._cmd_status = cmd_response.value
            if (
                cmd_packet.tag == CommandTag.WRITE_DCD
                and cmd_response.value != ResponseValue.WRITE_DATA_OK
            ):
                self._status_code = StatusCode.WRITE_DCD_FAILURE
                ret_val = False
            elif (
                cmd_packet.tag == CommandTag.WRITE_CSF
                and cmd_response.value != ResponseValue.WRITE_DATA_OK
            ):
                self._status_code = StatusCode.WRITE_CSF_FAILURE
                ret_val = False
            elif (
                cmd_packet.tag == CommandTag.WRITE_FILE
                and cmd_response.value != ResponseValue.WRITE_FILE_OK
            ):
                self._status_code = StatusCode.WRITE_IMAGE_FAILURE
                ret_val = False

        except Exception as exc:
            logger.info("RX-CMD: Timeout Error")
            raise SdpConnectionError(str(exc)) from exc

        if not ret_val and self._cmd_exception:
            raise SdpCommandError("SendData", self.status_code.tag)

        return ret_val

    def read(self, address: int, length: int, data_format: int = 32) -> Optional[bytes]:
        """Read value from register or memory at specified address.

        :param address: Start address of the first register or memory location
        :param length: Number of bytes to read
        :param data_format: Register access format in bits (8, 16, or 32)
        :return: Read data as bytes if successful, None otherwise
        """
        logger.info(f"TX-CMD: Read(address=0x{address:08X}, length={length}, format={data_format})")
        cmd_packet = CmdPacket(CommandTag.READ_REGISTER, address, data_format, length)
        if self._process_cmd(cmd_packet):
            return self._read_data(length)
        return None

    def read_safe(
        self,
        address: int,
        length: Optional[int] = None,
        data_format: int = 32,
        align_count: bool = False,
    ) -> Optional[bytes]:
        """Read value from register/memory at specified address.

        This method is safe because it validates input arguments and prevents fault execution.

        :param address: Start address of first register.
        :param length: Count of bytes to read, defaults to data_format byte size if not specified.
        :param data_format: Register access format in bits (8, 16, or 32).
        :param align_count: Align the count to data_format, defaults to False.
        :return: Read bytes if successful, None otherwise.
        :raises SdpError: If the data format is invalid or address is not properly aligned.
        """
        if data_format not in [8, 16, 32]:
            raise SdpError(f"Invalid data format '{data_format}'. Valid options are 8, 16, 32")
        # Check if start address value is aligned
        if (address % (data_format // 8)) > 0:
            raise SdpError(f"Address 0x{address:08X} not aligned to {data_format} bits")

        # if length is not specified, use byte-size of data_format
        length = length or data_format // 8

        # Align length value if requested
        if align_count:
            byte_alignment = data_format // 8
            length = math.ceil(length / byte_alignment) * byte_alignment

        return self.read(address, length, data_format)

    def write(self, address: int, value: int, count: int = 4, data_format: int = 32) -> bool:
        """Write value into register or memory at specified address.

        :param address: Start address of target register or memory location
        :param value: Value to write to the register or memory
        :param count: Number of bytes to write (maximum 4 bytes)
        :param data_format: Data access format in bits (8, 16, or 32)
        :return: True if write operation succeeded, False otherwise
        :raises SdpCommandError: If command failed and cmd_exception is enabled
        """
        logger.info(
            f"TX-CMD: Write(address=0x{address:08X}, value=0x{value:08X}, count={count}, format={data_format})"
        )
        cmd_packet = CmdPacket(CommandTag.WRITE_REGISTER, address, data_format, count, value)
        if not self._process_cmd(cmd_packet):
            return False
        status = self._read_status()
        if status != ResponseValue.WRITE_DATA_OK:
            self._status_code = StatusCode.WRITE_REGISTER_FAILURE
            if self._cmd_exception:
                raise SdpCommandError("WriteRegister", self.status_code.tag)
            return False
        return True

    def write_safe(self, address: int, value: int, count: int = 4, data_format: int = 32) -> bool:
        """Write value into register/memory at specified address.

        This method provides safe register/memory writing by validating input arguments,
        ensuring proper address alignment, and preventing fault execution. The count
        parameter is automatically aligned to the data format requirements.

        :param address: Start address of target register or memory location.
        :param value: Value to write to the register/memory.
        :param count: Number of bytes to write (maximum 4, will be aligned automatically).
        :param data_format: Register access format in bits (8, 16, or 32).
        :return: True if write operation succeeds, False otherwise.
        :raises SdpError: If address is not properly aligned or data_format is invalid.
        """
        if data_format not in [8, 16, 32]:
            raise SdpError(f"Invalid data format '{data_format}'. Valid options are 8, 16, 32")
        # Check if start address value is aligned
        if (address % (data_format // 8)) > 0:
            raise SdpError(f"Address 0x{address:08X} not aligned to {data_format} bits")
        # Align count value if doesn't
        align = count % (data_format // 8)
        if align > 0:
            count += (data_format // 8) - align
        count = min(count, 4)

        return self.write(address, value, count, data_format)

    def write_csf(self, address: int, data: bytes) -> bool:
        """Write CSF Data at specified address.

        This method sends a WRITE_CSF command to write Command Sequence File data
        to the target device at the specified memory address.

        :param address: Start address where CSF data will be written
        :param data: The CSF data in binary format to be written
        :return: True if the write operation succeeds, False otherwise
        """
        logger.info(f"TX-CMD: WriteCSF(address=0x{address:08X}, length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.WRITE_CSF, address, 0, len(data))
        return self._send_data(cmd_packet, data)

    def write_dcd(self, address: int, data: bytes) -> bool:
        """Write DCD values at specified address.

        This method sends a WRITE_DCD command to write Device Configuration Data (DCD)
        to the target device at the specified memory address.

        :param address: Start address where DCD data will be written
        :param data: The DCD data in binary format to be written
        :return: True if the write operation was successful, False otherwise
        """
        logger.info(f"TX-CMD: WriteDCD(address=0x{address:08X}, length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.WRITE_DCD, address, 0, len(data))
        return self._send_data(cmd_packet, data)

    def write_file(self, address: int, data: bytes) -> bool:
        """Write file or data to specified memory address.

        This method sends a WRITE_FILE command to write the provided data to the target
        device at the specified memory address.

        :param address: Target memory address where data will be written
        :param data: Binary data to be written to the device
        :return: True if the write operation succeeds, False otherwise
        """
        logger.info(f"TX-CMD: WriteFile(address=0x{address:08X}, length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.WRITE_FILE, address, 0, len(data))
        return self._send_data(cmd_packet, data)

    def skip_dcd(self) -> bool:
        """Skip DCD blob from loaded file.

        The method sends a SKIP_DCD_HEADER command to skip the Device Configuration Data
        blob during the boot process.

        :return: True if command executed successfully, False otherwise.
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True.
        """
        logger.info("TX-CMD: Skip DCD")
        cmd_packet = CmdPacket(CommandTag.SKIP_DCD_HEADER, 0, 0, 0)
        if not self._process_cmd(cmd_packet):
            return False
        status = self._read_status()
        if status != ResponseValue.SKIP_DCD_HEADER_OK:
            self._status_code = StatusCode.SKIP_DCD_HEADER_FAILURE
            if self._cmd_exception:
                raise SdpCommandError("SkipDcdHeader", self.status_code.tag)
            return False
        return True

    def jump_and_run(self, address: int) -> bool:
        """Jump to specified address and run code from there.

        This command instructs the device to transfer execution control to the specified
        memory address and begin executing code from that location.

        :param address: Destination memory address to jump to and execute code from.
        :return: True if the jump command was successfully processed, False otherwise.
        """
        logger.info(f"TX-CMD: Jump To Address: 0x{address:08X}")
        cmd_packet = CmdPacket(CommandTag.JUMP_ADDRESS, address, 0, 0)
        return self._process_cmd(cmd_packet)

    def read_status(self) -> Optional[int]:
        """Read error status from the device.

        This method sends a command to read the current error status and processes
        the response to extract the status value.

        :return: Status value if the command succeeds, None if it fails.
        """
        logger.info("TX-CMD: ReadStatus")
        if self._process_cmd(CmdPacket(CommandTag.ERROR_STATUS, 0, 0, 0)):
            return self._read_status()
        return None

    def set_baudrate(self, baudrate: int) -> bool:
        """Configure the UART baudrate on the device side.

        The default baudrate is 115200.

        :param baudrate: Baudrate value to be set on the device.
        :return: True if baudrate configuration was successful, False otherwise.
        """
        logger.info(f"TX-CMD: Set baudrate to: {baudrate}")
        cmd_packet = CmdPacket(CommandTag.SET_BAUDRATE, baudrate, 0, 0)
        return self._process_cmd(cmd_packet)
