#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 communication protocol implementation.

This module provides the core communication protocol for DK6 devices,
including ISP mode handling and low-level command/response processing.
"""

import logging
import struct
import time
from typing import Union

from spsdk.dk6.commands import (
    CmdPacket,
    CommandTag,
    GenericResponse,
    GetChipIdResponse,
    IspUnlockResponse,
    MemBlankCheckResponse,
    MemCloseResponse,
    MemEraseResponse,
    MemGetInfoResponse,
    MemOpenResponse,
    MemoryAccessValues,
    MemoryId,
    MemReadResponse,
    MemWriteResponse,
)
from spsdk.dk6.interface import Uart
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


DEFAULT_KEY = b"\x11\x22\x33\x44\x55\x66\x77\x88\x11\x22\x33\x44\x55\x66\x77\x88"


class IspMode(SpsdkEnum):
    """DK6 ISP (In-System Programming) mode enumeration.

    This enumeration defines the available ISP modes for DK6 protocol operations,
    including default mode, ISP functionality control, and device unlock operations.
    """

    DEFAULT = (0x00, "default", "Default")
    START_ISP = (0x01, "start_isp", "Start ISP Functionality")
    UNLOCK_DEVICE = (0x7F, "unlock_device", "Unlock device")
    EXTENDED_ISP_UNLOCK = (0x80, "extend_unlock", "Extended unlock")


class DK6Protocol:
    """DK6 communication protocol handler.

    This class provides a high-level interface for communicating with DK6 devices
    over UART, implementing the complete protocol for device operations including
    ISP unlocking, memory operations, and device information retrieval.

    :cvar MAX_PAYLOAD_SIZE: Maximum payload size supported by device buffer.
    """

    MAX_PAYLOAD_SIZE = 512  # max size of the payload, depends on the device buffer size

    def __init__(self, device: Uart) -> None:
        """Initialize DK6Protocol with UART device.

        :param device: Serial device that will be used for communication.
        :type device: Uart
        """
        self.uart = device

    def unlock_isp_default(self) -> IspUnlockResponse:
        """Unlock ISP sequence in default mode.

        Sends the unlock ISP command sequence using default mode, which restricts
        functionality to only allow the Get device info command to work.

        :return: Response object containing the unlock operation result.
        """
        self.uart.write(CommandTag.UNLOCK_ISP, b"\x00")
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def unlock_isp(
        self, mode: IspMode = IspMode.START_ISP, key: bytes = DEFAULT_KEY
    ) -> IspUnlockResponse:
        """Unlock ISP (In-System Programming) mode with authentication key.

        The method sends an unlock command to enable ISP functionality on the target device.
        If no key is provided, the default authentication key will be used.

        :param mode: ISP unlock mode specifying the operation type
        :param key: Authentication key for ISP unlock, either default or signed unlock key
        :return: Response object containing the unlock operation result
        """
        data = struct.pack(
            f"<B{len(key)}B",
            mode.tag,
            *key,
        )
        packet = CmdPacket(data)
        self.uart.write(CommandTag.UNLOCK_ISP, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def get_device_information(self) -> GetChipIdResponse:
        """Get device information from the connected device.

        Retrieves chip identification and ROM version information by sending a GET_CHIPID
        command to the device via UART communication.

        :return: GetChipIdResponse containing chip ID and chip (ROM) version information.
        """
        self.uart.write(CommandTag.GET_CHIPID, None)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_get_info(self, memory_id: Union[MemoryId, int] = MemoryId.FLASH) -> MemGetInfoResponse:
        """Get memory information for the specified memory ID.

        Retrieves detailed memory information such as size, length, and other properties
        for the given memory identifier through the DK6 protocol.

        :param memory_id: Memory identifier to query information for.
        :return: Memory information response containing size, length and other properties.
        """
        memory_id = memory_id if isinstance(memory_id, int) else memory_id.tag
        data = struct.pack(
            "<B",
            memory_id,
        )
        packet = CmdPacket(data)
        self.uart.write(CommandTag.MEM_GET_INFO, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_open(
        self,
        memory_id: MemoryId = MemoryId.FLASH,
        access: MemoryAccessValues = MemoryAccessValues.WRITE,
    ) -> MemOpenResponse:
        """Open given memory in the specified access mode.

        The method prepares and sends a memory open command packet to the target device
        and returns the response containing the memory handle.

        :param memory_id: Memory that will be opened, defaults to MemoryId.FLASH
        :param access: Access mode for the memory, defaults to MemoryAccessValues.WRITE
        :return: MemOpenResponse containing the memory handle
        """
        data = struct.pack(
            "<BB",
            memory_id.tag,
            access.tag,
        )
        packet = CmdPacket(data)
        self.uart.write(CommandTag.MEM_OPEN, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_read(
        self, address: int, length: int, handle: int = 0, mode: int = 0
    ) -> MemReadResponse:
        """Read data from memory at specified address.

        Reads a block of memory data from the target device using the specified
        handle and mode parameters.

        :param address: Start address to read from.
        :param length: Number of bytes to read.
        :param handle: Memory handle returned by mem_open operation.
        :param mode: Memory read mode to use.
        :return: MemReadResponse object containing the read data.
        """
        data = struct.pack("<BBII", handle, mode, address, length)
        packet = CmdPacket(data)
        self.uart.write(CommandTag.MEM_READ, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_write(
        self, address: int, length: int, data: bytes, handle: int = 0, mode: int = 0
    ) -> MemWriteResponse:
        """Write data to memory at specified address.

        This method writes the provided data to the target memory location using
        the DK6 protocol communication interface.

        :param address: Start address where data will be written.
        :param length: Number of bytes to be written.
        :param data: Binary data to be written to memory.
        :param handle: Memory handle returned by open memory command, defaults to 0.
        :param mode: Write operation mode, defaults to 0.
        :return: Memory write response containing operation status.
        """
        frame = struct.pack(f"<BBII{len(data)}B", handle, mode, address, length, *data)
        packet = CmdPacket(frame)

        self.uart.write(CommandTag.MEM_WRITE, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_close(self, handle: int = 0) -> MemCloseResponse:
        """Close the memory and finalize writing operations.

        This method sends a memory close command to finalize any pending write operations
        and properly close the memory handle that was previously opened.

        :param handle: Memory handle returned by open memory command, defaults to 0
        :return: Response object containing the result of the memory close operation
        """
        self.uart.write(CommandTag.MEM_CLOSE, handle.to_bytes(1, Endianness.BIG.value))
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_erase(
        self, address: int, length: int, handle: int = 0, mode: int = 0
    ) -> MemEraseResponse:
        """Erase a region of the selected memory.

        This command sends a memory erase request to the target device through UART communication.

        :param address: Start address of the memory region to erase.
        :param length: Number of bytes to be erased from the specified address.
        :param handle: Handle returned by open memory command, defaults to 0.
        :param mode: Erase mode specification, defaults to 0.
        :return: Memory erase response containing operation status and details.
        """
        frame = struct.pack("<BBII", handle, mode, address, length)
        packet = CmdPacket(frame)
        self.uart.write(CommandTag.MEM_ERASE, packet)
        response = self.uart.read()
        logger.debug(response.info())
        return response

    def mem_blank_check(
        self, address: int, length: int, handle: int = 0, mode: int = 0
    ) -> MemBlankCheckResponse:
        """Check if a region of the selected memory has been erased.

        This command verifies whether the specified memory region is in an erased state
        by performing a blank check operation on the target memory area.

        :param address: Start address of the memory region to check.
        :param length: Number of bytes to check for blank state.
        :param handle: Handle returned by open memory command, defaults to 0.
        :param mode: Blank check mode, defaults to 0.
        :return: MemBlankCheckResponse object containing the result of the blank check operation.
        """
        frame = struct.pack("<BBII", handle, mode, address, length)
        packet = CmdPacket(frame)
        self.uart.write(CommandTag.MEM_BLANK_CHECK, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def set_baud_rate(self, baudrate: int) -> None:
        """Set the UART communication baud rate.

        This method configures the baud rate for UART communication by sending
        a SET_BAUD command packet to the device and waiting for the change to take effect.

        :param baudrate: The baud rate value to be set for UART communication.
        """
        data = struct.pack(
            "<BI",
            0,
            baudrate,
        )
        packet = CmdPacket(data)
        self.uart.write(CommandTag.SET_BAUD, packet)
        time.sleep(0.1)

    def reset(self) -> GenericResponse:
        """Reset the device.

        Sends a reset command to the device via UART communication and waits for the response.

        :return: Response from the device after reset command execution.
        """
        self.uart.write(CommandTag.RESET, None)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def execute(self, address: int) -> GenericResponse:
        """Execute code at specified memory address.

        This command executes (runs) code in flash or RAM. The response is sent before
        execution jumps to the provided address.

        :param address: Memory address to start execution from.
        :return: Generic response from the device.
        """
        data = struct.pack("<I", address)
        packet = CmdPacket(data)

        self.uart.write(CommandTag.EXECUTE, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response
