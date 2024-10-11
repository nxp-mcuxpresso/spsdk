#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""DK6 Communication protocol."""
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
    """DK6 ISP modes."""

    DEFAULT = (0x00, "default", "Default")
    START_ISP = (0x01, "start_isp", "Start ISP Functionality")
    UNLOCK_DEVICE = (0x7F, "unlock_device", "Unlock device")
    EXTENDED_ISP_UNLOCK = (0x80, "extend_unlock", "Extended unlock")


class DK6Protocol:
    """Class implementing communication protocol for the DK6 devices."""

    MAX_PAYLOAD_SIZE = 512  # max size of the payload, depends on the device buffer size

    def __init__(self, device: Uart) -> None:
        """DK6Protocol constructor.

        :param device: serial device that will be used for communication.
        """
        self.uart = device

    def unlock_isp_default(self) -> IspUnlockResponse:
        """Sends unlock ISP sequence in default mode.

        It means that only Get device info command will work.

        :return: IspUnlockResponse
        """
        self.uart.write(CommandTag.UNLOCK_ISP, b"\x00")
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def unlock_isp(
        self, mode: IspMode = IspMode.START_ISP, key: bytes = DEFAULT_KEY
    ) -> IspUnlockResponse:
        """Unlocks ISP with the key.

        If the key is not provided, default will be used.

        :param mode: Unlock ISP mode, defaults to IspMode.START_ISP
        :param key: default key or signed unlock key, defaults to DEFAULT_KEY
        :return: IspUnlockResponse
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
        """Get device information.

        :return: GetChipIdResponse containing chip ID and chip (ROM) version
        """
        self.uart.write(CommandTag.GET_CHIPID, None)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_get_info(self, memory_id: Union[MemoryId, int] = MemoryId.FLASH) -> MemGetInfoResponse:
        """Get memory info about specified memory ID.

        :param memory_id: memory ID, defaults to MemoryId.FLASH
        :return: MemGetInfoResponse containing information like size, length etc.
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

        :param memory_id: memory that will be opened, defaults to MemoryId.FLASH
        :param access: access mode, defaults to MemoryAccessValues.READ
        :return: MemOpenResponse containing handle
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
        """Read from memory.

        :param address: start address
        :param length: length of data to be read in bytes
        :param handle: handle that was returned by mem_open, defaults to 0
        :param mode: Read mode, defaults to 0
        :return: MemReadResponse containing read data
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
        """Write to memory.

        :param address: start address
        :param length: number of bytes to be written
        :param data: data to be written
        :param handle: handle returned by open memory command, defaults to 0
        :param mode: write mode, defaults to 0
        :return: MemWriteResponse
        """
        frame = struct.pack(f"<BBII{len(data)}B", handle, mode, address, length, *data)
        packet = CmdPacket(frame)

        self.uart.write(CommandTag.MEM_WRITE, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_close(self, handle: int = 0) -> MemCloseResponse:
        """Close the memory. Finalize writing of the memory.

        :param handle: handle returned by open memory command, defaults to 0
        :return: MemCloseResponse
        """
        self.uart.write(CommandTag.MEM_CLOSE, handle.to_bytes(1, Endianness.BIG.value))
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def mem_erase(
        self, address: int, length: int, handle: int = 0, mode: int = 0
    ) -> MemEraseResponse:
        """This command erases a region of the selected memory.

        :param address: start address
        :param length: number of bytes to be erased
        :param handle: handle returned by open memory command, defaults to 0
        :param mode: erase mode, defaults to 0
        :return: MemEraseResponse
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
        """This command checks if a region of the selected memory has been erased.

        :param address: start address
        :param length: number of bytes to be erased
        :param handle: handle returned by open memory command, defaults to 0
        :param mode: erase mode, defaults to 0
        :return: MemEraseResponse
        """
        frame = struct.pack("<BBII", handle, mode, address, length)
        packet = CmdPacket(frame)
        self.uart.write(CommandTag.MEM_BLANK_CHECK, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def set_baud_rate(self, baudrate: int) -> None:
        """Sets baudrate.

        :param baudrate: int value of baudrate to be set
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
        """Resets device.

        :return: GenericResponse
        """
        self.uart.write(CommandTag.RESET, None)
        response = self.uart.read()
        logger.debug(response.info())

        return response

    def execute(self, address: int) -> GenericResponse:
        """This command executes (runs) code in flash or RAM.

        The response is sent before execution jumps to the provided address.

        :param address: Memory address to start execution from
        :return: GenericResponse
        """
        data = struct.pack("<I", address)
        packet = CmdPacket(data)

        self.uart.write(CommandTag.EXECUTE, packet)
        response = self.uart.read()
        logger.debug(response.info())

        return response
