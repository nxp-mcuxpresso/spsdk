#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK DK6 device management and communication interface.

This module provides high-level API for interacting with DK6 devices, including
device identification, memory operations, and communication management through
UART interface.
"""

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
    """DK6 Internal chip ID enumeration.

    This enumeration defines the internal chip identifiers used by the DK6 provisioning
    system for supported NXP MCU devices. Each entry contains the chip ID value, short
    name, and full device description.
    """

    JN5189 = (0x88888888, "JN5189", "JN5189 ESx")
    QN9090 = (0x1240C686, "QN9090", "QN9090")
    K32W041 = (0x1300C686, "K32W041", "K32W041")
    K32W061 = (0x1440C686, "K32W061", "K32W061")


class DK6DeviceId(SpsdkEnum):
    """DK6 Device ID enumeration for supported NXP devices.

    This enumeration defines the supported device identifiers for the DK6
    (Development Kit 6) family of NXP microcontrollers, including JN51xx,
    QN90xx, and K32W0xx series devices.
    """

    JN5188 = (5188, "JN5188")
    JN5189 = (5189, "JN5189")
    QN9030 = (9030, "QN9030")
    QN9090 = (9090, "QN9090")
    K32W041 = (32041, "K32W041")
    K32W061 = (32061, "K32W061")
    UNKNOWN = (0, "UNKNOWN")


class DK6Memory:
    """DK6 memory region descriptor.

    This class represents a memory region in DK6 devices, encapsulating all
    properties and characteristics of a specific memory area including its
    location, size, type, and access permissions.
    """

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
        """Initialize DK6Memory instance with memory configuration parameters.

        :param base_address: Base address where the memory region starts.
        :param length: Total size of the memory region in bytes.
        :param sector_size: Size of individual memory sector in bytes.
        :param mem_type: Type of memory (e.g., flash, RAM).
        :param mem_name: Human-readable name identifier for the memory.
        :param mem_id: Unique identifier for the memory region.
        :param access: Memory access permissions and capabilities.
        """
        self.base_address = base_address
        self.length = length
        self.sector_size = sector_size
        self.mem_type = mem_type
        self.mem_name = mem_name
        self.mem_id = mem_id
        self.access = access

    def __str__(self) -> str:
        """Get string representation of the memory region.

        Provides a formatted string containing all memory region properties including
        memory ID, base address, length, sector size, memory type, and access permissions.

        :return: Formatted string representation of the memory region.
        """
        return (
            f"\tMemoryId={self.mem_id.label}\n"
            f"\tBaseAddress={hex(self.base_address)}\n"
            f"\tLength={hex(self.length)}\n"
            f"\tSectorSize={hex(self.sector_size)}\n"
            f"\tMemoryType={self.mem_type.label}\n"
            f"\tAccess={self.access.label}\n"
        )

    def __repr__(self) -> str:
        """Return string representation of the DK6 device object.

        :return: String representation of the object.
        """
        return self.__str__()

    @property
    def end_address(self) -> int:
        """Calculate the end address of the memory region.

        The end address is computed by adding the base address and the length
        of the memory region.

        :return: The end address of the memory region.
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

    Validates memory access permissions, address ranges, and converts relative addresses to
    absolute addresses when needed.

    :param memory: DK6Memory object containing memory configuration and access permissions.
    :param access: Memory access type to be validated against allowed operations.
    :param length: Length of data in bytes to be accessed.
    :param relative: True if address is relative to memory base address, False for absolute.
    :param address: Memory address (relative or absolute based on relative parameter).
    :raises SPSDKError: If memory ID is not supported.
    :raises SPSDKError: If access type is not allowed for this memory.
    :raises SPSDKError: If the memory range is invalid or out of bounds.
    :return: Sanitized absolute memory address.
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
    """DK6 device communication interface.

    This class provides a high-level interface for communicating with DK6 devices,
    encapsulating the underlying serial communication protocol and device management.
    It handles device initialization, memory operations, and maintains device state
    including chip information and MAC address.
    """

    def __init__(
        self,
        device: SerialDevice,
    ) -> None:
        """DK6Device constructor.

        Initialize a new DK6Device instance for communication with DK6-compatible devices.

        :param device: SerialDevice that will be used for communication with the DK6 device.
        """
        self.memories: dict[int, DK6Memory] = {}
        self.chip_id: Union[GetChipIdResponse, None] = None
        self.uart = Uart(device)
        self.protocol = DK6Protocol(self.uart)
        self.mac_addr: Optional[bytes] = None
        self.dev_type: Optional[DK6DeviceId] = None
        self.initialized = False

    def __del__(self) -> None:
        """Clean up DK6 device resources and close connection.

        This destructor method ensures proper cleanup of the DK6 device connection
        when the object is being destroyed. It handles any potential errors during
        the closing process gracefully by logging them as debug messages.

        :raises SPSDKError: When device cannot be closed properly (logged only).
        """
        logger.info("Closing DK6 device")
        try:
            self.close()
        except SPSDKError as exc:
            logger.debug(f"Device cannot be closed: {exc}")

    def __enter__(self) -> "DK6Device":
        """Enter the runtime context of the DK6Device.

        This method is part of the context manager protocol, allowing the DK6Device
        to be used with 'with' statements for proper resource management.

        :return: The DK6Device instance itself.
        """
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[BaseException]] = None,
        exception_value: Optional[BaseException] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Exit the context manager and close the DK6 device.

        This method is called automatically when exiting a 'with' statement block.
        It ensures proper cleanup by closing the device connection.

        :param exception_type: Type of exception that caused the context to exit, if any.
        :param exception_value: Exception instance that caused the context to exit, if any.
        :param traceback: Traceback object associated with the exception, if any.
        """
        logger.info("Closing DK6 device")
        self.close()

    def _split_data(self, data: bytes) -> list[bytes]:
        """Split data into chunks if it exceeds maximum packet size.

        The method divides input data into smaller chunks based on the protocol's
        maximum payload size to ensure proper transmission.

        :param data: Binary data to be split into transmission-ready chunks.
        :return: List of data chunks, each within the maximum packet size limit.
        """
        max_packet_size = self.protocol.MAX_PAYLOAD_SIZE
        return [data[i : i + max_packet_size] for i in range(0, len(data), max_packet_size)]

    def close(self) -> None:
        """Close UART device.

        Closes the UART connection and resets the initialization state of the device.

        :raises SPSDKError: When the device cannot be closed.
        """
        if self.uart:
            self.uart.close()
        self.initialized = False

    def add_memory(self, memory: DK6Memory) -> None:
        """Add memory to the list of available memories.

        :param memory: DK6Memory object to be added to the device's memory collection.
        """
        self.memories.update({memory.mem_id.tag: memory})

    def get_memory(self, memory_id: MemoryId) -> DK6Memory:
        """Get DK6Memory based on memory_id.

        :param memory_id: MemoryId of the desired memory
        :raises SPSDKError: When the memory cannot be fetched
        :return: DK6Memory object corresponding to the specified memory ID
        """
        if self.memories:
            memory = self.memories.get(memory_id.tag)
            if memory:
                return memory
        raise SPSDKError(f"Memory with {memory_id} is not fetched")

    def get_mac_str(self) -> str:
        """Get MAC address in string format.

        The method formats the MAC address bytes into a colon-separated hexadecimal string
        representation. If no MAC address is available, returns "N/A".

        :return: String containing MAC address in format "XX:XX:XX:XX:XX:XX" or "N/A" if not available.
        """
        if self.mac_addr:
            return ":".join(f"{b:02X}" for b in self.mac_addr)
        return "N/A"

    def add_memory_from_response(self, memory_response: MemGetInfoResponse) -> None:
        """Add memory configuration from device memory information response.

        This method processes a MemGetInfoResponse and creates a DK6Memory object with the
        provided memory configuration parameters. The memory is only added if the response
        status indicates success.

        :param memory_response: Memory information response containing device memory details.
        :raises: No explicit exceptions raised by this method.
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

        This method performs the complete initialization sequence for a DK6 device including
        ISP unlocking, device information retrieval, memory discovery, MAC address reading,
        and device type identification. If the device is already initialized, the method
        will skip the initialization process.

        :raises SPSDKError: When device communication fails or device type cannot be determined.
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

        The method performs memory reading operation by validating the request, opening memory
        in specified access mode, splitting the request into chunks based on maximum payload
        size, reading data sequentially, and closing the memory connection.

        1. Make a validation of the read request
        2. Open memory in given access mode
        3. Split read request to chunks of max(MAX_PAYLOAD_SIZE, requested_len)
        4. Read data
        5. Close memory

        :param memory_id: Memory identifier specifying which memory to access.
        :param address: Starting address for the read operation.
        :param length: Number of bytes to read from memory.
        :param access: Memory access mode for the operation.
        :param progress_callback: Optional callback function to report reading progress.
        :param relative: Whether address is relative to memory base address.
        :raises SPSDKError: Memory ID is not supported.
        :raises SPSDKError: Access is not allowed.
        :raises SPSDKError: Invalid range.
        :return: Read data as bytes.
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

        The method performs memory write operation by validating the request, opening memory in given
        access mode, splitting write request to chunks, writing data, and closing memory.

        1. Make a validation of the read request
        2. Open memory in given access mode
        3. Split write request to chunks of max(MAX_PAYLOAD_SIZE, requested_len)
        4. Write data
        5. Close memory

        :param memory_id: Memory ID of the memory to be used.
        :param address: Start address for writing data.
        :param length: Length of data to be written.
        :param data: Data bytes to be written to memory.
        :param access: Memory access mode, defaults to MemoryAccessValues.ALL.
        :param progress_callback: Optional callback function for progress reporting.
        :param relative: True if address is relative to the memory base address.
        :raises SPSDKError: Memory ID is not supported.
        :raises SPSDKError: Access is not allowed.
        :raises SPSDKError: Invalid range.
        :raises SPSDKError: No response from device.
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

        The method validates the erase request, opens memory in given access mode, erases data,
        optionally verifies with blank check, and closes memory.
        1. Make a validation of the read request
        2. Open memory in given access mode
        4. Erase data
        5. Optionally verify with blank check
        6. Close memory

        :param memory_id: MemoryID of the memory to be used.
        :param address: Start address for memory erase operation.
        :param length: Length of data to be erased in bytes.
        :param access: Memory access value, defaults to MemoryAccessValues.ALL.
        :param progress_callback: Progress callback function used in CLI, defaults to None.
        :param relative: True if address is relative to the memory base address.
        :param verify: True for erase verification by memory blank check.
        :raises SPSDKError: Memory ID is not supported.
        :raises SPSDKError: Access is not allowed.
        :raises SPSDKError: Invalid range.
        :raises SPSDKError: Memory erase failed.
        :raises SPSDKError: Memory blank check failed.
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
        """Reset the device.

        This method performs a device reset operation through the protocol interface
        and validates the operation was successful.

        :raises SPSDKError: When the reset operation fails.
        """
        result = self.protocol.reset()

        if result.status != StatusCode.OK:
            raise SPSDKError("Reset failed")

    def set_baud_rate(self, baudrate: int) -> None:
        """Set baud rate for the DK6 device communication.

        :param baudrate: The baud rate value to set for serial communication.
        """
        self.protocol.set_baud_rate(baudrate)
