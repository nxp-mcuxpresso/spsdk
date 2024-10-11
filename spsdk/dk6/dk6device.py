#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""DK6 Device high level API."""
import logging
from types import TracebackType
from typing import Callable, Optional, Type, Union

from spsdk.dk6.commands import (
    GetChipIdResponse,
    MemGetInfoResponse,
    MemoryAccessValues,
    MemoryId,
    MemoryType,
    StatusCode,
)
from spsdk.dk6.interface import Uart
from spsdk.dk6.protocol import DK6Protocol
from spsdk.dk6.serial_device import SerialDevice
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


MAX_MEM_ID = 9

MAC_MEM_ADDR = 0x9FC70
DEV_TYPE_ADDR = 0x9FC60
MAC_LEN = 8
DEV_LEN = 4


class DK6ChipIdInternal(SpsdkEnum):
    """DK6 Internal chip ID."""

    JN5189 = (0x88888888, "JN5189", "JN5189 ESx")
    QN9090 = (0x1240C686, "QN9090", "QN9090")
    K32W041 = (0x1300C686, "K32W041", "K32W041")
    K32W061 = (0x1440C686, "K32W061", "K32W061")


class DK6DeviceId(SpsdkEnum):
    """DK6 Device IDs."""

    JN5188 = (5188, "JN5188")
    JN5189 = (5189, "JN5189")
    QN9030 = (9030, "QN9030")
    QN9090 = (9090, "QN9090")
    K32W041 = (32041, "K32W041")
    K32W061 = (32061, "K32W061")
    UNKNOWN = (0, "UNKNOWN")


class DK6Memory:
    """Class that holds information about the DK6 devices memory."""

    def __init__(
        self,
        base_address: int,
        length: int,
        sector_size: int,
        mem_type: MemoryType,
        mem_name: str,
        mem_id: MemoryId,
        access: MemoryAccessValues,
    ) -> None:
        """DK6Memory Constructor.

        :param base_address: Memory base address
        :param length: Memory length
        :param sector_size: Memory sector size
        :param mem_type: Memory type
        :param mem_name: Memory name
        :param mem_id: Memory ID
        :param access: Memory access
        """
        self.base_address = base_address
        self.length = length
        self.sector_size = sector_size
        self.mem_type = mem_type
        self.mem_name = mem_name
        self.mem_id = mem_id
        self.access = access

    def __str__(self) -> str:
        return (
            f"\tMemoryId={self.mem_id.label}\n"
            f"\tBaseAddress={hex(self.base_address)}\n"
            f"\tLength={hex(self.length)}\n"
            f"\tSectorSize={hex(self.sector_size)}\n"
            f"\tMemoryType={self.mem_type.label}\n"
            f"\tAccess={self.access.label}\n"
        )

    def __repr__(self) -> str:
        """Return obj representation.

        :return: return obj str
        """
        return self.__str__()

    @property
    def end_address(self) -> int:
        """End address of Memory.

        :return: End address
        """
        return self.base_address + self.length


def check_memory(
    memory: DK6Memory,
    access: MemoryAccessValues,
    length: int,
    relative: bool,
    address: int,
) -> int:
    """Check memory range and return sanitized address value.

    :param memory: DK6Memory
    :param access: access type
    :param length: length of data
    :param relative: true if address is relative to base address
    :param address: memory address
    :raises SPSDKError: if memory ID is not supported
    :raises SPSDKError: if access is not allowed
    :raises SPSDKError: if the memory range is invalid
    :return: Sanitized memory address
    """
    if memory is None:
        raise SPSDKError("Memory ID is not supported")

    if access.tag > memory.access.tag:
        raise SPSDKError(
            f"Access {access.tag} is not allowed. Only allowed is {hex(memory.access.tag)}"
        )

    if relative:
        address += memory.base_address
        mem_check = (address + length) > memory.end_address
    else:
        mem_check = ((address + length) > memory.end_address) or (address < memory.base_address)

    if mem_check:
        raise SPSDKError(
            f"Invalid range. The range is {hex(memory.base_address)}:{hex(memory.end_address)}"
            f" or 0:{hex(memory.length)} in relative mode"
        )

    return address


class DK6Device:
    """Class that represents DK6 device.

    It's a high level class that encapsulates communication interface and protocol
    """

    def __init__(
        self,
        device: SerialDevice,
    ) -> None:
        """DK6Device constructor.

        :param device: SerialDevice that will be used for communication
        :param baudrate: communication baudrate, defaults to 115200
        """
        self.memories: dict[int, DK6Memory] = {}
        self.chip_id: Union[GetChipIdResponse, None] = None
        self.uart = Uart(device)
        self.protocol = DK6Protocol(self.uart)
        self.mac_addr: Optional[bytes] = None
        self.dev_type: Optional[DK6DeviceId] = None
        self.initialized = False

    def __del__(self) -> None:
        logger.info("Closing DK6 device")
        try:
            self.close()
        except SPSDKError as exc:
            logger.debug(f"Device cannot be closed: {exc}")

    def __enter__(self) -> "DK6Device":
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]] = None,
        exception_value: Optional[BaseException] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        logger.info("Closing DK6 device")
        self.close()

    def _split_data(self, data: bytes) -> list[bytes]:
        """Split data to send if necessary.

        :param data: Data to send
        :return: List of data splices
        """
        max_packet_size = self.protocol.MAX_PAYLOAD_SIZE
        return [data[i : i + max_packet_size] for i in range(0, len(data), max_packet_size)]

    def close(self) -> None:
        """Close UART device.

        :raises: SPSDKError: When the device cannot be closed
        """
        if self.uart:
            self.uart.close()
        self.initialized = False

    def add_memory(self, memory: DK6Memory) -> None:
        """Add memory to the list of available memories.

        :param memory: DK6Memory
        """
        self.memories.update({memory.mem_id.tag: memory})

    def get_memory(self, memory_id: MemoryId) -> DK6Memory:
        """Get DK6Memory based on memory_id.

        :param memory_id: MemoryId of the desired memory
        :raises SPSDKError: When the memory cannot be fetched
        :return: DK6Memory
        """
        if self.memories:
            memory = self.memories.get(memory_id.tag)
            if memory:
                return memory
        raise SPSDKError(f"Memory with {memory_id} is not fetched")

    def get_mac_str(self) -> str:
        """Get MAC address in string format.

        :return: string containing MAC address FF:FF..
        """
        if self.mac_addr:
            return ":".join(f"{b:02X}" for b in self.mac_addr)
        return "N/A"

    def add_memory_from_response(self, memory_response: MemGetInfoResponse) -> None:
        """Add memory from MemGetInfoResponse.

        :param memory_response: MemGetInfoResponse
        """
        if memory_response.status == StatusCode.OK:
            memory = DK6Memory(
                base_address=memory_response.base_addr,
                length=memory_response.length,
                sector_size=memory_response.sector_size,
                mem_type=MemoryType.from_tag(memory_response.mem_type),
                mem_name=memory_response.mem_name,
                mem_id=MemoryId.from_tag(memory_response.memory_id),
                access=MemoryAccessValues.from_tag(memory_response.access),
            )
            self.add_memory(memory)

    def init(self) -> None:
        """Initialize DK6 device for communication.

        1. Unlock ISP default
        2. Get device information
        3. Unlock ISP with default key
        4. Get info about memories
        """
        if not self.initialized:
            logger.info("Initializing device... Sending UNLOCK ISP default")
            self.protocol.unlock_isp_default()
            logger.info("Obtaining device information")
            self.chip_id = self.protocol.get_device_information()
            logger.info("Unlocking ISP")
            self.protocol.unlock_isp()

            logger.info("Getting information about memories")
            for mem_id in range(MAX_MEM_ID):
                mem_info = self.protocol.mem_get_info(mem_id)
                self.add_memory_from_response(mem_info)

            self.protocol.mem_close()

            logger.info("Reading MAC address")
            self.protocol.mem_open(MemoryId.Config)
            response = self.protocol.mem_read(MAC_MEM_ADDR, MAC_LEN)
            self.mac_addr = response.data
            self.protocol.mem_close()

            logger.info("Reading device type")
            self.protocol.mem_open(MemoryId.Config)
            response = self.protocol.mem_read(DEV_TYPE_ADDR, DEV_LEN)
            try:
                self.dev_type = DK6DeviceId.from_tag(
                    int.from_bytes(response.data, Endianness.LITTLE.value)
                )
            except SPSDKError:
                self.dev_type = DK6DeviceId.UNKNOWN

            self.protocol.mem_close()
            self.initialized = True
        else:
            logger.info("Skipping Initialization, device is already initialized")

    def read_memory(
        self,
        memory_id: MemoryId,
        address: int,
        length: int,
        access: MemoryAccessValues = MemoryAccessValues.WRITE,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        relative: bool = False,
    ) -> bytes:
        """Read memory from the DK6 device.

        1. Make a validation of the read request
        2. Open memory in given access mode
        3. Split read request to chunks of max(MAX_PAYLOAD_SIZE, requested_len)
        4. Read data
        5. Close memory

        :param memory_id: MemoryID of the memory to be used
        :param address: start address
        :param length: length of data
        :param access: memory access value, defaults to MemoryAccessValues.WRITE
        :param progress_callback: progress callback used in CLI, defaults to None
        :param relative: True if address is relative to the memory base address
        :raises SPSDKError: Memory ID is not supported
        :raises SPSDKError: Access is not allowed
        :raises SPSDKError: Invalid range
        :return: Read data
        """
        memory = self.get_memory(memory_id)
        address = check_memory(memory, access, length, relative, address)
        logger.info(f"READ command, memory {memory_id}, address {address}, length {length}")
        self.protocol.mem_open(memory_id, access)

        payload_size = self.protocol.MAX_PAYLOAD_SIZE
        packets = length // payload_size
        remainder = length % payload_size

        if remainder:
            packets += 1

        data = b""

        for idx in range(packets):
            if idx == packets - 1 and remainder:
                data_len = remainder
            else:
                data_len = payload_size
            response = self.protocol.mem_read(address + idx * payload_size, data_len)
            data += response.data
            if progress_callback:
                progress_callback(len(data), length)
        self.protocol.mem_close()

        return data

    def write_memory(
        self,
        memory_id: MemoryId,
        address: int,
        length: int,
        data: bytes,
        access: MemoryAccessValues = MemoryAccessValues.ALL,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        relative: bool = False,
    ) -> None:
        """Write memory to the DK6 device.

        1. Make a validation of the read request
        2. Open memory in given access mode
        3. Split write request to chunks of max(MAX_PAYLOAD_SIZE, requested_len)
        4. Write data
        5. Close memory

        :param memory_id: MemoryID of the memory to be used
        :param address: start address
        :param length: length of data
        :param data: data to be written
        :param access: memory access value, defaults to MemoryAccessValues.WRITE
        :param progress_callback: progress callback used in CLI, defaults to None
        :param relative: True if address is relative to the memory base address
        :raises SPSDKError: Memory ID is not supported
        :raises SPSDKError: Access is not allowed
        :raises SPSDKError: Invalid range
        :raises SPSDKError: No response from device
        """
        memory = self.get_memory(memory_id)

        address = check_memory(memory, access, length, relative, address)

        self.protocol.mem_open(memory_id, access)

        data_chunks = self._split_data(data)

        total_sent = 0
        total_to_send = len(data)

        try:
            for data_chunk in data_chunks:
                status = self.protocol.mem_write(
                    address + total_sent, len(data_chunk), data_chunk
                ).status
                if status != StatusCode.OK:
                    raise SPSDKError("Sending of data failed")
                total_sent += len(data_chunk)
                if progress_callback:
                    progress_callback(total_sent, total_to_send)

        except TimeoutError as exc:
            logger.error("RX: No Response, Timeout Error !")
            raise SPSDKError("No Response from Device") from exc

        self.protocol.mem_close()

    def erase_memory(
        self,
        memory_id: MemoryId,
        address: int,
        length: int,
        access: MemoryAccessValues = MemoryAccessValues.ALL,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        relative: bool = False,
        verify: bool = False,
    ) -> None:
        """Erase memory of DK6 device.

        # 1. Make a validation of the read request
        # 2. Open memory in given access mode
        # 4. Erase data
        # 5. Optionally verify with blank check
        # 6. Close memory

        :param memory_id: MemoryID of the memory to be used
        :param address: start address
        :param length: length of data
        :param access: memory access value, defaults to MemoryAccessValues.WRITE
        :param progress_callback: progress callback used in CLI, defaults to None
        :param relative: True if address is relative to the memory base address
        :param verify: True for erase verification by memory blank check
        :raises SPSDKError: Memory ID is not supported
        :raises SPSDKError: Access is not allowed
        :raises SPSDKError: Invalid range
        :raises SPSDKError: No response from device
        """
        memory = self.get_memory(memory_id)

        if progress_callback:
            progress_callback(1, 4)

        address = check_memory(memory, access, length, relative, address)

        self.protocol.mem_open(memory_id, access)
        result = self.protocol.mem_erase(address, length)
        if result.status != StatusCode.OK:
            raise SPSDKError("Memory erase failed")

        if progress_callback:
            progress_callback(3, 4)
        if verify:
            result_check = self.protocol.mem_blank_check(address, length)
            if result_check.status != StatusCode.OK:
                raise SPSDKError("Memory blank check failed")
        self.protocol.mem_close()

        if progress_callback:
            progress_callback(4, 4)

    def reset(self) -> None:
        """Resets device."""
        result = self.protocol.reset()

        if result.status != StatusCode.OK:
            raise SPSDKError("Reset failed")

    def set_baud_rate(self, baudrate: int) -> None:
        """Set baud rate."""
        self.protocol.set_baud_rate(baudrate)
