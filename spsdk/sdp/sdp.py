#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDP communication protocol."""
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
    """Serial Downloader Protocol."""

    @property
    def status_code(self) -> StatusCode:
        """Get status code from SDP."""
        return self._status_code

    @property
    def hab_status(self) -> int:
        """Get the response value from hab."""
        return self._hab_status

    @property
    def cmd_status(self) -> int:
        """Get the response value from the command."""
        return self._cmd_status

    @property
    def is_opened(self) -> bool:
        """Indicates whether the underlying interface is open.

        :return: True if device is open, False if it's closed
        """
        return self._interface.is_opened

    def __init__(self, interface: SDPDeviceTypes, cmd_exception: bool = False) -> None:
        """Initialize the SDP object.

        :param device: Interface to a device
        :param cmd_exception: True if commands should raise in exception, defaults to False
        """
        self._hab_status = 0
        self._cmd_exception = cmd_exception
        self._status_code = StatusCode.SUCCESS
        self._cmd_status = 0
        self._interface = interface

    def __enter__(self) -> "SDP":
        self.open()
        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        self.close()

    def open(self) -> None:
        """Connect to i.MX device."""
        logger.info(f"Connect: {str(self._interface)}")
        self._interface.open()

    def close(self) -> None:
        """Disconnect i.MX device."""
        self._interface.close()

    def _process_cmd(self, cmd_packet: CmdPacket) -> bool:
        """Process Command Packet.

        :param cmd_packet: Command packet object
        :return: True if success else False.
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True
        :raises SdpConnectionError: Timeout or Connection error
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
            self._hab_status = response.value
            if response.value != ResponseValue.UNLOCKED:
                self._status_code = StatusCode.HAB_IS_LOCKED

        return True

    def _read_status(self) -> int:
        """Read status value.

        :return: Status code
        :raises SdpConnectionError: Timeout
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

        :param length: Count of bytes
        :return: bytes read if the read operation is successful else None
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True
        :raises SdpConnectionError: Timeout or Connection error
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
        """Send data to target.

        :param cmd_packet: Command packet object
        :param data: array with data to send
        :return: True if the write operation is successful
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True
        :raises SdpConnectionError: Timeout or Connection error
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
        """Read value from reg/mem at specified address.

        :param address: Start address of first register
        :param length: Count of bytes
        :param data_format: Register access format 8, 16, 32 bits
        :return: Return bytes if success else None.
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
        """Read value from reg/mem at specified address.

        This method is safe, because is validating input arguments and prevents fault execution.

        :param address: Start address of first register
        :param length: Count of bytes
        :param data_format: Register access format 8, 16, 32 bits
        :param align_count: Align the count to data_format , default False
        :return: Return bytes if success else None.
        :raises SdpError: If the address is not properly aligned
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
        """Write value into reg/mem at specified address.

        :param address: Start address of first register
        :param value: Register value
        :param count: Count of bytes (max 4)
        :param data_format: Register access format 8, 16, 32 bits
        :return: Return True if success else False.
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True
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
        """Write value into reg/mem at specified address.

        This method is safe, because is validating input arguments and prevents fault execution.

        :param address: Start address of first register
        :param value: Register value
        :param count: Count of bytes (max 4)
        :param data_format: Register access format 8, 16, 32 bits
        :return: Return True if success else False.
        :raises SdpError: If the address is not properly aligned or invalid data_format
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

        :param address: Start Address
        :param data: The CSF data in binary format
        :return: Return True if success else False.
        """
        logger.info(f"TX-CMD: WriteCSF(address=0x{address:08X}, length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.WRITE_CSF, address, 0, len(data))
        return self._send_data(cmd_packet, data)

    def write_dcd(self, address: int, data: bytes) -> bool:
        """Write DCD values at specified address.

        :param address: Start Address
        :param data: The DCD data in binary format
        :return: Return True if success else False.
        """
        logger.info(f"TX-CMD: WriteDCD(address=0x{address:08X}, length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.WRITE_DCD, address, 0, len(data))
        return self._send_data(cmd_packet, data)

    def write_file(self, address: int, data: bytes) -> bool:
        """Write File/Data at specified address.

        :param address: Start Address
        :param data: The boot image data in binary format
        :return: Return True if success else False.
        """
        logger.info(f"TX-CMD: WriteFile(address=0x{address:08X}, length={len(data)})")
        cmd_packet = CmdPacket(CommandTag.WRITE_FILE, address, 0, len(data))
        return self._send_data(cmd_packet, data)

    def skip_dcd(self) -> bool:
        """Skip DCD blob from loaded file.

        :return: Return True if success else False.
        :raises SdpCommandError: If command failed and the 'cmd_exception' is set to True
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

        :param address: Destination address
        :return: Return True if success else False.
        """
        logger.info(f"TX-CMD: Jump To Address: 0x{address:08X}")
        cmd_packet = CmdPacket(CommandTag.JUMP_ADDRESS, address, 0, 0)
        return self._process_cmd(cmd_packet)

    def read_status(self) -> Optional[int]:
        """Read Error Status.

        :return: Return status value if success else None
        """
        logger.info("TX-CMD: ReadStatus")
        if self._process_cmd(CmdPacket(CommandTag.ERROR_STATUS, 0, 0, 0)):
            return self._read_status()
        return None

    def set_baudrate(self, baudrate: int) -> bool:
        """Configure the UART baudrate on the device side.

        The default baudrate is 115200.

        :param baudrate: Baudrate to be set
        :return: Return True if success else False.
        """
        logger.info(f"TX-CMD: Set baudrate to: {baudrate}")
        cmd_packet = CmdPacket(CommandTag.SET_BAUDRATE, baudrate, 0, 0)
        return self._process_cmd(cmd_packet)
