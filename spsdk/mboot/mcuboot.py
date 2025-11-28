#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MCU bootloader communication interface.

This module provides the McuBoot class for communicating with NXP MCU bootloaders,
enabling secure provisioning operations, firmware updates, and device configuration
through various transport protocols.
"""

import logging
import struct
import time
from types import TracebackType
from typing import Callable, Optional, Sequence, Type, Union

from spsdk.mboot.commands import (
    CmdPacket,
    CmdResponse,
    CommandFlag,
    CommandTag,
    EL2GOCommandGroup,
    FlashReadOnceResponse,
    FlashReadResourceResponse,
    GenerateKeyBlobSelect,
    GenericResponse,
    GetPropertyResponse,
    KeyProvisioningResponse,
    KeyProvOperation,
    NoResponse,
    ReadMemoryResponse,
    TrustProvDevHsmDsc,
    TrustProvisioningResponse,
    TrustProvOperation,
    TrustProvWpc,
)
from spsdk.mboot.error_codes import StatusCode, stringify_status_code
from spsdk.mboot.exceptions import (
    McuBootCommandError,
    McuBootConnectionError,
    McuBootDataAbortError,
    McuBootError,
    SPSDKError,
)
from spsdk.mboot.memories import ExtMemId, ExtMemRegion, FlashRegion, MemoryRegion, RamRegion
from spsdk.mboot.properties import (
    AvailableCommandsValue,
    PropertyTag,
    PropertyValueBase,
    Version,
    get_properties,
    get_property_tag_label,
    parse_property_value,
)
from spsdk.mboot.protocol.base import MbootProtocolBase
from spsdk.utils.family import FamilyRevision
from spsdk.utils.interfaces.device.usb_device import UsbDevice

logger = logging.getLogger(__name__)


########################################################################################################################
# McuBoot Class
########################################################################################################################
class McuBoot:  # pylint: disable=too-many-public-methods
    """McuBoot communication interface for NXP bootloader operations.

    This class provides a high-level interface for communicating with NXP MCU bootloaders,
    handling command execution, status management, and data transfer operations. It supports
    various bootloader protocols and manages connection state and error handling.

    :cvar DEFAULT_MAX_PACKET_SIZE: Default maximum packet size for data transfers.
    """

    DEFAULT_MAX_PACKET_SIZE = 32

    @property
    def status_code(self) -> int:
        """Return status code of the last operation.

        :return: Status code as integer value.
        """
        return self._status_code

    @property
    def status_string(self) -> str:
        """Return status string.

        Convert the internal status code to a human-readable string representation.

        :return: Human-readable status string corresponding to the current status code.
        """
        return stringify_status_code(self._status_code)

    @property
    def is_opened(self) -> bool:
        """Check if the device interface is currently opened.

        :return: True if the device interface is opened, False otherwise.
        """
        return self._interface.is_opened

    def __init__(
        self,
        interface: MbootProtocolBase,
        cmd_exception: bool = False,
        family: Optional[FamilyRevision] = None,
    ) -> None:
        """Initialize the McuBoot object.

        :param interface: The instance of communication interface class
        :param cmd_exception: True to throw McuBootCommandError on any error;
                False to set status code only
                Note: some operation might raise McuBootCommandError is all cases
        :param family: Optional family revision specification
        """
        self._cmd_exception = cmd_exception
        self._status_code = StatusCode.SUCCESS.tag
        self._interface = interface
        self.family = family
        self.reopen = False
        self.enable_data_abort = False
        self._pause_point: Optional[int] = None
        self.available_commands_lst: list[CommandTag] = []
        self.max_packet_size: Optional[int] = None

    def __enter__(self) -> "McuBoot":
        """Enter the runtime context of the McuBoot object.

        This method is used as a context manager entry point that ensures the McuBoot
        connection is properly opened and configured for use within a 'with' statement.

        :return: The McuBoot instance itself for use in the context manager.
        """
        self.reopen = True
        self.open()
        return self

    def __exit__(
        self,
        exception_type: Optional[Type[Exception]] = None,
        exception_value: Optional[Exception] = None,
        traceback: Optional[TracebackType] = None,
    ) -> None:
        """Close the MCU boot interface context manager.

        This method is called automatically when exiting a 'with' statement context.
        It ensures proper cleanup of the MCU boot interface connection.

        :param exception_type: Type of exception that caused the context to exit, if any.
        :param exception_value: Exception instance that caused the context to exit, if any.
        :param traceback: Traceback object associated with the exception, if any.
        """
        self.close()

    def _process_cmd(self, cmd_packet: CmdPacket) -> CmdResponse:
        """Process command packet and return response.

        Sends the command packet to the target device through the interface and waits for response.
        Handles timeout scenarios and validates command execution status.

        :param cmd_packet: Command packet to be sent to the target device.
        :return: Command response received from the target device.
        :raises McuBootConnectionError: Device is not opened or connection issue occurred.
        :raises McuBootCommandError: Error during command execution on the target device.
        """
        if not self.is_opened:
            logger.info("TX: Device not opened")
            raise McuBootConnectionError("Device not opened")

        logger.debug(f"TX-PACKET: {str(cmd_packet)}")

        try:
            self._interface.write_command(cmd_packet)
            response = self._interface.read()
        except TimeoutError:
            self._status_code = StatusCode.NO_RESPONSE.tag
            logger.debug("RX-PACKET: No Response, Timeout Error !")
            response = NoResponse(cmd_tag=cmd_packet.header.tag)

        assert isinstance(response, CmdResponse)
        logger.debug(f"RX-PACKET: {str(response)}")
        self._status_code = response.status

        if self._cmd_exception and self._status_code != StatusCode.SUCCESS:
            raise McuBootCommandError(CommandTag.get_label(cmd_packet.header.tag), response.status)
        logger.info(f"CMD: Status: {self.status_string}")
        return response

    def _read_data(
        self,
        cmd_tag: CommandTag,
        length: int,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bytes:
        """Read data from device.

        This method continuously reads data from the MCU device interface until the specified
        length is reached or an error occurs. It handles timeout errors and provides progress
        updates through an optional callback function.

        :param cmd_tag: Tag indicating the read command type.
        :param length: Number of bytes to read from the device.
        :param progress_callback: Optional callback function for progress updates, called with
            (current_bytes, total_bytes) parameters.
        :raises McuBootConnectionError: Device is not opened or interface communication problem.
        :raises McuBootCommandError: Error during command execution on the target device.
        :return: Data read from the device, truncated to requested length if necessary.
        """
        data = b""

        if not self.is_opened:
            logger.error("RX: Device not opened")
            raise McuBootConnectionError("Device not opened")
        while True:
            try:
                response = self._interface.read()
            except McuBootDataAbortError as e:
                logger.error(f"RX: {e}")
                logger.info("Try increasing the timeout value")
                response = self._interface.read()
            except TimeoutError:
                self._status_code = StatusCode.NO_RESPONSE.tag
                logger.error("RX: No Response, Timeout Error !")
                response = NoResponse(cmd_tag=cmd_tag.tag)
                break

            if isinstance(response, bytes):
                data += response
                if progress_callback:
                    progress_callback(len(data), length)

            elif isinstance(response, GenericResponse):
                logger.debug(f"RX-PACKET: {str(response)}")
                self._status_code = response.status
                if response.cmd_tag == cmd_tag:
                    break

        if len(data) < length or self.status_code != StatusCode.SUCCESS:
            status_info = (
                StatusCode.get_label(self._status_code)
                if self._status_code in StatusCode.tags()
                else f"0x{self._status_code:08X}"
            )
            logger.debug(f"CMD: Received {len(data)} from {length} Bytes, {status_info}")
            if self._cmd_exception:
                assert isinstance(response, CmdResponse)
                raise McuBootCommandError(cmd_tag.label, response.status)
        else:
            logger.info(f"CMD: Successfully Received {len(data)} from {length} Bytes")

        return data[:length] if len(data) > length else data

    def _send_data(
        self,
        cmd_tag: CommandTag,
        data: list[bytes],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bool:
        """Send data part of specific command to the target device.

        The method sends data chunks sequentially to the target device and optionally
        reports progress through a callback. It handles connection errors and command
        execution errors appropriately.

        :param cmd_tag: Tag indicating the command type being executed.
        :param data: List of data chunks to send to the target device.
        :param progress_callback: Optional callback function for progress updates with
            signature (bytes_sent, total_bytes).
        :raises McuBootConnectionError: Device is disconnected or timeout occurred.
        :raises McuBootCommandError: Error during command execution on the target.
        :return: True if all data was sent successfully, False otherwise.
        """
        if not self.is_opened:
            logger.info("TX: Device Disconnected")
            raise McuBootConnectionError("Device Disconnected !")

        total_sent = 0
        total_to_send = sum(len(chunk) for chunk in data)
        # this difference is applicable for load-image and program-aeskey commands
        expect_response = cmd_tag != CommandTag.NO_COMMAND
        self._interface.allow_abort = self.enable_data_abort
        try:
            for data_chunk in data:
                self._interface.write_data(data_chunk)
                total_sent += len(data_chunk)
                if progress_callback:
                    progress_callback(total_sent, total_to_send)
                if self._pause_point and total_sent > self._pause_point:
                    time.sleep(0.1)
                    self._pause_point = None

            if expect_response:
                response = self._interface.read()
        except TimeoutError as e:
            self._status_code = StatusCode.NO_RESPONSE.tag
            logger.error("RX: No Response, Timeout Error !")
            raise McuBootConnectionError("No Response from Device") from e
        except SPSDKError as e:
            logger.error(f"RX: {e}")
            if expect_response:
                response = self._interface.read()
            else:
                self._status_code = StatusCode.SENDING_OPERATION_CONDITION_ERROR.tag

        if expect_response:
            assert isinstance(response, CmdResponse)
            logger.debug(f"RX-PACKET: {str(response)}")
            self._status_code = response.status
            if response.status != StatusCode.SUCCESS:
                status_info = (
                    StatusCode.get_label(self._status_code)
                    if self._status_code in StatusCode.tags()
                    else f"0x{self._status_code:08X}"
                )
                logger.debug(f"CMD: Send Error, {status_info}")
                if self._cmd_exception:
                    raise McuBootCommandError(cmd_tag.label, response.status)
                return False

        logger.info(f"CMD: Successfully Send {total_sent} out of {total_to_send} Bytes")
        return total_sent == total_to_send

    def _get_max_packet_size(self) -> int:
        """Get maximum packet size for communication.

        The method first checks for a cached value, then queries the device for the
        MAX_PACKET_SIZE property. If the property cannot be retrieved, it falls back
        to a default value and logs a warning.

        :return: Maximum packet size in bytes.
        :raises McuBootError: When communication with the device fails during property retrieval.
        """
        if self.max_packet_size is not None:
            logger.debug(f"Using cached max_packet_size={self.max_packet_size}")
            return self.max_packet_size

        packet_size_property = None
        try:
            packet_size_property = self.get_property(prop_tag=PropertyTag.MAX_PACKET_SIZE)
        except McuBootError:
            pass
        if packet_size_property is None:
            packet_size_property = [self.DEFAULT_MAX_PACKET_SIZE]
            logger.warning(
                f"CMD: Unable to get MAX PACKET SIZE, using: {self.DEFAULT_MAX_PACKET_SIZE}"
            )
        self.max_packet_size = packet_size_property[0]
        logger.info(f"CMD: Max Packet Size = {self.max_packet_size}")
        return self.max_packet_size

    def _split_data(self, data: bytes) -> list[bytes]:
        """Split data to send if necessary.

        The method checks if the interface requires data splitting and divides the data
        into chunks based on the maximum packet size if needed.

        :param data: Data bytes to be split for transmission.
        :return: List of data chunks, either single chunk if no split needed or multiple chunks.
        """
        if not self._interface.need_data_split:
            return [data]
        max_packet_size = self._get_max_packet_size()
        return [data[i : i + max_packet_size] for i in range(0, len(data), max_packet_size)]

    def open(self) -> None:
        """Connect to the device.

        Establishes connection to the target device using the configured interface.
        Logs the connection attempt with interface details.

        :raises SPSDKConnectionError: If the connection to the device fails.
        :raises SPSDKError: If the interface is not properly configured.
        """
        logger.info(f"Connect: {str(self._interface)}")
        self._interface.open()

    def close(self) -> None:
        """Disconnect from the device.

        Closes the connection to the MCU device through the underlying interface.
        This method should be called when communication with the device is no longer needed
        to properly release resources and terminate the connection.
        """
        logger.info(f"Closing: {str(self._interface)}")
        self._interface.close()

    def get_property_list(self) -> list[PropertyValueBase]:
        """Get a list of available properties.

        Retrieves all available properties for the target device by iterating through
        known property tags and attempting to read their values. Properties that cannot
        be read are skipped, and successfully read properties are parsed and included
        in the result list.

        :return: List of available properties with their parsed values.
        :raises McuBootCommandError: Failure to read properties list.
        :raises McuBootError: Property values cannot be parsed.
        """
        property_list: list[PropertyValueBase] = []
        for property_tag in get_properties(self.family):
            try:
                values = self.get_property(property_tag)
            except McuBootCommandError:
                continue

            if values:
                prop = parse_property_value(property_tag, values)
                if prop is None:
                    raise McuBootError("Property values cannot be parsed")
                property_list.append(prop)

        self._status_code = StatusCode.SUCCESS.tag
        if not property_list:
            self._status_code = StatusCode.FAIL.tag
            if self._cmd_exception:
                raise McuBootCommandError("GetPropertyList", self.status_code)

        return property_list

    @property
    def available_commands(self) -> list[CommandTag]:
        """Get a list of supported commands.

        Retrieves the available commands from the MCU boot loader. If the commands list is already
        cached, returns the cached version. Otherwise, queries the device for available commands
        using the AVAILABLE_COMMANDS property and caches the result.

        :raises McuBootCommandError: When unable to retrieve available commands property.
        :return: List of supported command tags from the MCU boot loader.
        """
        if self.available_commands_lst:
            return self.available_commands_lst

        values = None
        props = None

        try:
            values = self.get_property(PropertyTag.AVAILABLE_COMMANDS)
        except McuBootCommandError:
            pass

        if values:
            props = parse_property_value(PropertyTag.AVAILABLE_COMMANDS, values)

        if isinstance(props, AvailableCommandsValue):
            self.available_commands_lst = [CommandTag.from_tag(tag) for tag in props.tags]

        return self.available_commands_lst

    def _get_internal_flash(self) -> list[FlashRegion]:
        """Get information about the internal flash.

        Retrieves flash region information by iterating through available flash indices and querying
        properties for start address, size, and sector size. The iteration continues until no more
        valid flash regions are found or an error occurs.

        :raises McuBootCommandError: When flash property retrieval fails.
        :return: List of FlashRegion objects containing flash memory information.
        """
        index = 0
        mdata: list[FlashRegion] = []
        start_address = 0
        while True:
            try:
                values = self.get_property(PropertyTag.FLASH_START_ADDRESS, index)
                if not values:
                    break
                if index == 0:
                    start_address = values[0]
                elif start_address == values[0]:
                    break
                region_start = values[0]
                values = self.get_property(PropertyTag.FLASH_SIZE, index)
                if not values:
                    break
                region_size = values[0]
                values = self.get_property(PropertyTag.FLASH_SECTOR_SIZE, index)
                if not values:
                    break
                region_sector_size = values[0]
                mdata.append(
                    FlashRegion(
                        index=index,
                        start=region_start,
                        size=region_size,
                        sector_size=region_sector_size,
                    )
                )
                index += 1
            except McuBootCommandError:
                break

        return mdata

    def _get_internal_ram(self) -> list[RamRegion]:
        """Get information about the internal RAM regions.

        Iterates through available RAM regions by querying the device properties for RAM start
        addresses and sizes. The iteration continues until no more regions are found or an error
        occurs.

        :raises McuBootCommandError: When communication with the device fails during property
            retrieval.
        :return: List of RamRegion objects containing information about each internal RAM region.
        """
        index = 0
        mdata: list[RamRegion] = []
        start_address = 0
        while True:
            try:
                values = self.get_property(PropertyTag.RAM_START_ADDRESS, index)
                if not values:
                    break
                if index == 0:
                    start_address = values[0]
                elif start_address == values[0]:
                    break
                start = values[0]
                values = self.get_property(PropertyTag.RAM_SIZE, index)
                if not values:
                    break
                size = values[0]
                mdata.append(RamRegion(index=index, start=start, size=size))
                index += 1
            except McuBootCommandError:
                break

        return mdata

    def _get_ext_memories(self) -> list[ExtMemRegion]:
        """Get information about the external memories.

        Retrieves a list of external memory regions supported by the target device by querying
        the device properties. The method first checks the MCU boot version to determine which
        external memory types are supported, then queries each memory type for its attributes.

        :return: List of ExtMemRegion objects representing external memories supported by device.
        :raises SPSDKError: If no response to get property command.
        :raises SPSDKError: If other communication error occurs.
        """
        ext_mem_list: list[ExtMemRegion] = []
        # The items of ExtMemId enum may not have unique tags
        ext_mem_ids: Sequence[int] = list(set(ExtMemId.tags()))
        try:
            values = self.get_property(PropertyTag.CURRENT_VERSION)
        except McuBootCommandError:
            values = None

        if not values and self._status_code == StatusCode.UNKNOWN_PROPERTY:
            self._status_code = StatusCode.SUCCESS.tag
            return ext_mem_list

        if not values:
            raise SPSDKError("No response to get property command")

        if Version(values[0]) <= Version("2.0.0"):
            # old versions mboot support only Quad SPI memory
            ext_mem_ids = [ExtMemId.QUAD_SPI0.tag]

        for mem_id in ext_mem_ids:
            try:
                values = self.get_property(PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, mem_id)
            except McuBootCommandError:
                values = None

            if not values:  # pragma: no cover  # corner-cases are currently untestable without HW
                if self._status_code == StatusCode.UNKNOWN_PROPERTY:
                    break

                if self._status_code in [
                    StatusCode.QSPI_NOT_CONFIGURED,
                    StatusCode.INVALID_ARGUMENT,
                ]:
                    continue

                if self._status_code == StatusCode.MEMORY_NOT_CONFIGURED:
                    ext_mem_list.append(ExtMemRegion(mem_id=mem_id))

                if self._status_code == StatusCode.SUCCESS:
                    raise SPSDKError("Other Error")

            else:
                ext_mem_list.append(ExtMemRegion(mem_id=mem_id, raw_values=values))
        return ext_mem_list

    def get_memory_list(self) -> dict:
        """Get list of embedded memories.

        Retrieves information about all available memory regions including internal flash,
        internal RAM, and external memories connected to the MCU.

        :return: Dictionary with memory regions. Keys: 'internal_flash' (optional) - list of
                 internal flash regions, 'internal_ram' (optional) - list of internal RAM
                 regions, 'external_mems' (optional) - list of external memory regions.
        :raises McuBootCommandError: Error reading the memory list.
        """
        memory_list: dict[str, Sequence[MemoryRegion]] = {}

        # Internal FLASH
        mdata = self._get_internal_flash()
        if mdata:
            memory_list["internal_flash"] = mdata

        # Internal RAM
        ram_data = self._get_internal_ram()
        if ram_data:
            memory_list["internal_ram"] = ram_data

        # External Memories
        ext_mem_list = self._get_ext_memories()
        if ext_mem_list:
            memory_list["external_mems"] = ext_mem_list

        self._status_code = StatusCode.SUCCESS.tag
        if not memory_list:
            self._status_code = StatusCode.FAIL.tag
            if self._cmd_exception:
                raise McuBootCommandError("GetMemoryList", self.status_code)

        return memory_list

    def flash_erase_all(self, mem_id: int = 0) -> bool:
        """Erase complete flash memory without recovering flash security section.

        This operation will erase all flash memory content except for the flash security section,
        which remains intact to preserve security configurations.

        :param mem_id: Memory identifier specifying which memory to erase (default is 0).
        :return: True if erase operation completed successfully, False otherwise.
        """
        logger.info(f"CMD: FlashEraseAll(mem_id={mem_id})")
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_ALL, CommandFlag.NONE.tag, mem_id)
        response = self._process_cmd(cmd_packet)
        return response.status == StatusCode.SUCCESS

    def flash_erase_region(self, address: int, length: int, mem_id: int = 0) -> bool:
        """Erase specified range of flash memory.

        This method erases a contiguous region of flash memory starting at the given
        address for the specified length. The operation is performed on the target
        device through the MCU boot protocol.

        :param address: Start address of the flash region to erase.
        :param length: Number of bytes to erase from the start address.
        :param mem_id: Memory identifier specifying which memory to erase (default is 0).
        :return: True if erase operation completed successfully, False otherwise.
        """
        logger.info(
            f"CMD: FlashEraseRegion(address=0x{address:08X}, length={length}, mem_id={mem_id})"
        )
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(
            CommandTag.FLASH_ERASE_REGION, CommandFlag.NONE.tag, address, length, mem_id
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def read_memory(
        self,
        address: int,
        length: int,
        mem_id: int = 0,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        fast_mode: bool = False,
    ) -> Optional[bytes]:
        """Read data from MCU memory.

        The method implements a workaround for better USB-HID reliability by splitting large reads
        into smaller packets when not in fast mode. Fast mode transfers data in single operation
        but may be unreliable for USB-HID interfaces.

        :param address: Start address in memory to read from.
        :param length: Number of bytes to read.
        :param mem_id: Memory identifier, defaults to 0.
        :param progress_callback: Optional callback function to report progress with signature
                                 (bytes_read, total_bytes).
        :param fast_mode: Enable fast mode for USB-HID transfer, may be unreliable.
        :return: Data read from memory, empty bytes on command failure, or None on read failure.
        """
        logger.info(f"CMD: ReadMemory(address=0x{address:08X}, length={length}, mem_id={mem_id})")
        mem_id = _clamp_down_memory_id(memory_id=mem_id)

        # workaround for better USB-HID reliability
        if isinstance(self._interface.device, UsbDevice) and not fast_mode:
            payload_size = self._get_max_packet_size()
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

                cmd_packet = CmdPacket(
                    CommandTag.READ_MEMORY,
                    CommandFlag.NONE.tag,
                    address + idx * payload_size,
                    data_len,
                    mem_id,
                )
                cmd_response = self._process_cmd(cmd_packet)
                if cmd_response.status == StatusCode.SUCCESS:
                    data += self._read_data(CommandTag.READ_MEMORY, data_len)
                    if progress_callback:
                        progress_callback(len(data), length)
                    if self._status_code == StatusCode.NO_RESPONSE:
                        logger.warning(f"CMD: NO RESPONSE, received {len(data)}/{length} B")
                        return data
                else:
                    return b""

            return data

        cmd_packet = CmdPacket(
            CommandTag.READ_MEMORY, CommandFlag.NONE.tag, address, length, mem_id
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, ReadMemoryResponse)
            return self._read_data(CommandTag.READ_MEMORY, cmd_response.length, progress_callback)
        return None

    def write_memory(
        self,
        address: int,
        data: bytes,
        mem_id: int = 0,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> bool:
        """Write data into MCU memory.

        The method writes the provided data to the specified memory address in the MCU.
        Data is automatically split into chunks for transmission.

        :param address: Start address in memory where data will be written.
        :param data: Bytes data to be written to memory.
        :param mem_id: Memory ID (see ExtMemId), use 0 for internal memory.
        :param progress_callback: Optional callback function for progress updates with
            (current, total) parameters.
        :return: True if write operation succeeded, False otherwise.
        """
        logger.info(
            f"CMD: WriteMemory(address=0x{address:08X}, length={len(data)}, mem_id={mem_id})"
        )
        data_chunks = self._split_data(data=data)
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(
            CommandTag.WRITE_MEMORY, CommandFlag.HAS_DATA_PHASE.tag, address, len(data), mem_id
        )
        if self._process_cmd(cmd_packet).status == StatusCode.SUCCESS:
            return self._send_data(CommandTag.WRITE_MEMORY, data_chunks, progress_callback)
        return False

    def fill_memory(self, address: int, length: int, pattern: int = 0xFFFFFFFF) -> bool:
        """Fill MCU memory with specified pattern.

        The method fills a specified memory region with a given 32-bit pattern value.
        All parameters must be word-aligned for proper operation.

        :param address: Start address in MCU memory (must be word aligned).
        :param length: Number of words to fill (must be word aligned).
        :param pattern: 32-bit pattern value to fill memory with.
        :return: True if operation successful, False otherwise.
        """
        logger.info(
            f"CMD: FillMemory(address=0x{address:08X}, length={length}, pattern=0x{pattern:08X})"
        )
        cmd_packet = CmdPacket(
            CommandTag.FILL_MEMORY, CommandFlag.NONE.tag, address, length, pattern
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def flash_security_disable(self, backdoor_key: bytes) -> bool:
        """Disable flash security by using backdoor key.

        The method sends a flash security disable command to the MCU using the provided 8-byte
        backdoor key. The key bytes are reordered (reversed in 4-byte chunks) before transmission.

        :param backdoor_key: The backdoor key value as bytes array, must be exactly 8 bytes long.
        :return: True if flash security was successfully disabled, False otherwise.
        :raises McuBootError: If the backdoor_key is not exactly 8 bytes long.
        """
        if len(backdoor_key) != 8:
            raise McuBootError("Backdoor key must by 8 bytes long")
        logger.info(f"CMD: FlashSecurityDisable(backdoor_key={backdoor_key!r})")
        key_high = backdoor_key[0:4][::-1]
        key_low = backdoor_key[4:8][::-1]
        cmd_packet = CmdPacket(
            CommandTag.FLASH_SECURITY_DISABLE, CommandFlag.NONE.tag, data=key_high + key_low
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def get_property(
        self, prop_tag: Union[PropertyTag, int], index: int = 0
    ) -> Optional[list[int]]:
        """Get specified property value from the MCU device.

        Retrieves a property value using the get-property command. The property can be
        related to device capabilities, memory regions, or external memory configurations.

        :param prop_tag: Property tag identifier from PropertyTag enum or integer value
        :param index: External memory ID or internal memory region index (depends on property type)
        :return: List of integers representing the property value; None if no response from device
        :raises McuBootError: If received invalid get-property response
        """
        property_id, label = get_property_tag_label(prop_tag, self.family)
        logger.info(f"CMD: GetProperty({label}, index={index!r})")
        cmd_packet = CmdPacket(CommandTag.GET_PROPERTY, CommandFlag.NONE.tag, property_id, index)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            if isinstance(cmd_response, GetPropertyResponse):
                return cmd_response.values
            raise McuBootError(f"Received invalid get-property response: {str(cmd_response)}")
        return None

    def set_property(self, prop_tag: Union[PropertyTag, int], value: int) -> bool:
        """Set value of specified property.

        This method sets a property value on the target device using the SetProperty command.
        The property is identified by its tag and the new value is applied.

        :param prop_tag: Property tag identifier from PropertyTag enum or integer value.
        :param value: New value to set for the specified property.
        :return: True if property was set successfully, False otherwise.
        """
        property_id, label = get_property_tag_label(prop_tag, self.family)
        logger.info(f"CMD: SetProperty({label}, value=0x{value:08X})")
        cmd_packet = CmdPacket(CommandTag.SET_PROPERTY, CommandFlag.NONE.tag, property_id, value)
        cmd_response = self._process_cmd(cmd_packet)
        return cmd_response.status == StatusCode.SUCCESS

    def receive_sb_file(
        self,
        data: bytes,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        check_errors: bool = False,
    ) -> bool:
        """Receive SB file.

        Sends Secure Binary file data to the target device for processing. The method handles
        data chunking, progress reporting, and error checking during transmission.

        :param data: SB file data to be transmitted to the device.
        :param progress_callback: Optional callback function for progress updates during transmission.
        :param check_errors: Check for ABORT_FRAME and related errors on USB interface between packets.
            When False, significantly improves USB transfer speed (~20x) but final status may be
            misleading. If receive-sb-file fails, re-run with this flag set to True.
        :return: True if successful, False if any problem occurred.
        """
        logger.info(f"CMD: ReceiveSBfile(data_length={len(data)})")
        data_chunks = self._split_data(data=data)
        cmd_packet = CmdPacket(
            CommandTag.RECEIVE_SB_FILE, CommandFlag.HAS_DATA_PHASE.tag, len(data)
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            self.enable_data_abort = check_errors
            if isinstance(self._interface.device, UsbDevice):
                try:
                    # pylint: disable=import-outside-toplevel   # import only if needed to save time
                    from spsdk.sbfile.sb2.images import ImageHeaderV2

                    sb2_header = ImageHeaderV2.parse(data=data)
                    self._pause_point = sb2_header.first_boot_tag_block * 16
                except SPSDKError:
                    pass
                try:
                    # pylint: disable=import-outside-toplevel   # import only if needed to save time
                    from spsdk.sbfile.sb31.images import SecureBinary31Header

                    sb3_header = SecureBinary31Header.parse(data=data)
                    self._pause_point = sb3_header.image_total_length
                except SPSDKError:
                    pass
            result = self._send_data(CommandTag.RECEIVE_SB_FILE, data_chunks, progress_callback)
            self.enable_data_abort = False
            return result
        return False

    def execute(self, address: int, argument: int, sp: int) -> bool:  # pylint: disable=invalid-name
        """Execute program on a given address using the stack pointer.

        :param address: Jump address (must be word aligned)
        :param argument: Function arguments address
        :param sp: Stack pointer address
        :return: False in case of any problem; True otherwise
        """
        logger.info(
            f"CMD: Execute(address=0x{address:08X}, argument=0x{argument:08X}, SP=0x{sp:08X})"
        )
        cmd_packet = CmdPacket(CommandTag.EXECUTE, CommandFlag.NONE.tag, address, argument, sp)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def call(self, address: int, argument: int) -> bool:
        """Call function at specified address with given argument.

        :param address: Call address (must be word aligned)
        :param argument: Function arguments address
        :return: False in case of any problem; True otherwise
        """
        logger.info(f"CMD: Call(address=0x{address:08X}, argument=0x{argument:08X})")
        cmd_packet = CmdPacket(CommandTag.CALL, CommandFlag.NONE.tag, address, argument)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def reset(self, timeout: int = 2000, reopen: bool = True) -> bool:
        """Reset MCU and reconnect if enabled.

        The method sends a reset command to the MCU, closes the current connection,
        and optionally reopens it after a specified timeout period.

        :param timeout: The maximal waiting time in milliseconds for reopen connection.
        :param reopen: True for reopen connection after HW reset else False.
        :return: False in case of any problem; True otherwise.
        :raises McuBootConnectionError: Reset command failed or reopen failed.
        """
        logger.info("CMD: Reset MCU")
        cmd_packet = CmdPacket(CommandTag.RESET, CommandFlag.NONE.tag)
        ret_val = False
        status = self._process_cmd(cmd_packet).status
        self.close()
        ret_val = True

        if status not in [StatusCode.NO_RESPONSE, StatusCode.SUCCESS]:
            ret_val = False
            if self._cmd_exception:
                raise McuBootConnectionError("Reset command failed")

        if status == StatusCode.NO_RESPONSE:
            logger.warning("Did not receive response from reset command, ignoring it")
            self._status_code = StatusCode.SUCCESS.tag

        if reopen:
            time.sleep(timeout / 1000)
            try:
                self.open()
            except SPSDKError as e:
                ret_val = False
                if self._cmd_exception:
                    raise McuBootConnectionError("reopen failed") from e

        return ret_val

    def flash_erase_all_unsecure(self) -> bool:
        """Erase complete flash memory and recover flash security section.

        This command performs a mass erase of the entire flash memory and restores
        the flash security settings to their default unsecured state.

        :return: True if the erase operation completed successfully, False otherwise.
        """
        logger.info("CMD: FlashEraseAllUnsecure")
        cmd_packet = CmdPacket(CommandTag.FLASH_ERASE_ALL_UNSECURE, CommandFlag.NONE.tag)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def efuse_read_once(self, index: int) -> Optional[int]:
        """Read from MCU flash program once region.

        The method reads a 32-bit value from the specified index in the MCU's
        one-time programmable (OTP) flash region.

        :param index: Start index in the flash program once region.
        :return: Read value as 32-bit integer, or None if operation failed.
        """
        logger.info(f"CMD: FlashReadOnce(index={index})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_ONCE, CommandFlag.NONE.tag, index, 4)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, FlashReadOnceResponse)
            return cmd_response.values[0]
        return None

    def efuse_program_once(self, index: int, value: int, verify: bool = False) -> bool:
        """Write into MCU once program region (OCOTP).

        This method programs a 4-byte value into the One-Time Programmable (OTP) memory at the
        specified index. Optionally verifies the write operation by reading back and comparing
        the value as a bitmask.

        :param index: Start index in the OTP memory region.
        :param value: 4-byte integer value to program into OTP.
        :param verify: If True, verify programming by reading back and comparing as bitmask.
        :return: True if programming succeeded, False if any error occurred.
        """
        logger.info(
            f"CMD: FlashProgramOnce(index={index}, value=0x{value:X}) "
            f"with{'' if verify else 'out'} verification."
        )
        cmd_packet = CmdPacket(CommandTag.FLASH_PROGRAM_ONCE, CommandFlag.NONE.tag, index, 4, value)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status != StatusCode.SUCCESS:
            return False
        if verify:
            read_value = self.efuse_read_once(index=index & ((1 << 24) - 1))
            if read_value is None:
                return False
            # We check only a bitmask, because OTP allows to burn individual bits separately
            # Some other bits may have been already written
            if read_value & value == value:
                return True
            # It may happen that ROM will not report error when attempting to write into locked OTP
            # In such case we substitute the original SUCCESS code with custom-made OTP_VERIFY_FAIL
            self._status_code = StatusCode.OTP_VERIFY_FAIL.tag
            return False
        return cmd_response.status == StatusCode.SUCCESS

    def flash_read_once(self, index: int, count: int = 4) -> Optional[bytes]:
        """Read from MCU flash program once region.

        The method reads data from the MCU's one-time programmable (OTP) flash region.
        Maximum read size is 8 bytes per operation.

        :param index: Start index in the program once region
        :param count: Number of bytes to read (must be 4 or 8)
        :return: Data read from the program once region; None if operation fails
        :raises SPSDKError: When invalid count of bytes. Must be 4 or 8
        """
        if count not in (4, 8):
            raise SPSDKError("Invalid count of bytes. Must be 4 or 8")
        logger.info(f"CMD: FlashReadOnce(index={index}, bytes={count})")
        cmd_packet = CmdPacket(CommandTag.FLASH_READ_ONCE, CommandFlag.NONE.tag, index, count)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, FlashReadOnceResponse)
            return cmd_response.data
        return None

    def flash_program_once(self, index: int, data: bytes) -> bool:
        """Write into MCU flash program once region (max 8 bytes).

        :param index: Start index for the program once region.
        :param data: Input data aligned to 4 or 8 bytes.
        :return: False in case of any problem; True otherwise.
        :raises SPSDKError: When invalid length of data. Must be aligned to 4 or 8 bytes.
        """
        if len(data) not in (4, 8):
            raise SPSDKError("Invalid length of data. Must be aligned to 4 or 8 bytes")
        logger.info(f"CMD: FlashProgramOnce(index={index!r}, data={data!r})")
        cmd_packet = CmdPacket(
            CommandTag.FLASH_PROGRAM_ONCE, CommandFlag.NONE.tag, index, len(data), data=data
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def flash_read_resource(self, address: int, length: int, option: int = 1) -> Optional[bytes]:
        """Read resource of flash module.

        The method reads data from specific flash memory areas like IFR or Firmware ID.
        The length must be aligned to 4 bytes boundary.

        :param address: Start address to read from.
        :param length: Number of bytes to read (must be aligned to 4 bytes).
        :param option: Area to be read. 0 means Flash IFR, 1 means Flash Firmware ID.
        :raises McuBootError: When the length is not aligned to 4 bytes.
        :return: Data from the resource; None in case of failure.
        """
        if length % 4:
            raise McuBootError("The number of bytes to read is not aligned to the 4 bytes")
        logger.info(
            f"CMD: FlashReadResource(address=0x{address:08X}, length={length}, option={option})"
        )
        cmd_packet = CmdPacket(
            CommandTag.FLASH_READ_RESOURCE, CommandFlag.NONE.tag, address, length, option
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, FlashReadResourceResponse)
            return self._read_data(CommandTag.FLASH_READ_RESOURCE, cmd_response.length)
        return None

    def configure_memory(self, address: int, mem_id: int) -> bool:
        """Configure memory with specified parameters.

        This method configures a memory region at the given address with the specified memory ID.
        The configuration data is expected to be located at the provided memory address.

        :param address: The address in memory where configuration data is located.
        :param mem_id: Memory identifier specifying which memory to configure.
        :return: True if configuration was successful, False if any problem occurred.
        """
        logger.info(f"CMD: ConfigureMemory({mem_id}, address=0x{address:08X})")
        cmd_packet = CmdPacket(CommandTag.CONFIGURE_MEMORY, CommandFlag.NONE.tag, mem_id, address)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def reliable_update(self, address: int) -> bool:
        """Execute reliable update command on the target device.

        This command instructs the bootloader to perform a reliable update using
        firmware stored at the specified address.

        :param address: Memory address where the new firmware is stored.
        :return: True if the reliable update command was successful, False otherwise.
        """
        logger.info(f"CMD: ReliableUpdate(address=0x{address:08X})")
        cmd_packet = CmdPacket(CommandTag.RELIABLE_UPDATE, CommandFlag.NONE.tag, address)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def generate_key_blob(
        self,
        dek_data: bytes,
        key_sel: int = GenerateKeyBlobSelect.OPTMK.tag,
        count: int = 72,
    ) -> Optional[bytes]:
        """Generate Key Blob.

        This method creates a key blob by wrapping a Data Encryption Key (DEK) using the
        specified Blob Key Encryption Key (BKEK). The process involves sending the DEK data
        to the target device and retrieving the generated encrypted key blob.

        :param dek_data: Data Encryption Key as bytes to be wrapped into key blob
        :param key_sel: Select the BKEK used to wrap the BK (default: OPTMK/FUSES)
        :param count: Expected key blob size in bytes (default: 72 for AES128bit)
        :return: Generated key blob as bytes, None if operation fails
        """
        logger.info(
            f"CMD: GenerateKeyBlob(dek_len={len(dek_data)}, key_sel={key_sel}, count={count})"
        )
        data_chunks = self._split_data(data=dek_data)
        cmd_response = self._process_cmd(
            CmdPacket(
                CommandTag.GENERATE_KEY_BLOB,
                CommandFlag.HAS_DATA_PHASE.tag,
                key_sel,
                len(dek_data),
                0,
            )
        )
        if cmd_response.status != StatusCode.SUCCESS:
            return None
        if not self._send_data(CommandTag.GENERATE_KEY_BLOB, data_chunks):
            return None
        cmd_response = self._process_cmd(
            CmdPacket(CommandTag.GENERATE_KEY_BLOB, CommandFlag.NONE.tag, key_sel, count, 1)
        )
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, ReadMemoryResponse)
            return self._read_data(CommandTag.GENERATE_KEY_BLOB, cmd_response.length)
        return None

    def kp_enroll(self) -> bool:
        """Key provisioning: Enroll Command (start PUF).

        This command initiates the Physical Unclonable Function (PUF) enrollment process
        for key provisioning operations.

        :return: True if enrollment was successful, False otherwise.
        """
        logger.info("CMD: [KeyProvisioning] Enroll")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING, CommandFlag.NONE.tag, KeyProvOperation.ENROLL.tag
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_set_intrinsic_key(self, key_type: int, key_size: int) -> bool:
        """Key provisioning: Generate Intrinsic Key.

        This method generates an intrinsic key with the specified type and size using the key
        provisioning functionality.

        :param key_type: Type of the key to generate.
        :param key_size: Size of the key in bytes.
        :return: True if key generation was successful, False otherwise.
        """
        logger.info(f"CMD: [KeyProvisioning] SetIntrinsicKey(type={key_type}, key_size={key_size})")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.NONE.tag,
            KeyProvOperation.SET_INTRINSIC_KEY.tag,
            key_type,
            key_size,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_write_nonvolatile(self, mem_id: int = 0) -> bool:
        """Write the key to a nonvolatile memory during key provisioning.

        This method performs a key provisioning operation to store the previously loaded
        key into nonvolatile memory for persistent storage.

        :param mem_id: The memory ID where the key should be written (default: 0)
        :return: True if the operation was successful, False otherwise
        """
        logger.info(f"CMD: [KeyProvisioning] WriteNonVolatileMemory(mem_id={mem_id})")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.NONE.tag,
            KeyProvOperation.WRITE_NON_VOLATILE.tag,
            mem_id,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_read_nonvolatile(self, mem_id: int = 0) -> bool:
        """Load the key from a nonvolatile memory to bootloader.

        This method performs key provisioning operation to read a key from nonvolatile
        memory and load it into the bootloader for further use.

        :param mem_id: The memory ID to read from.
        :return: True if operation successful, False otherwise.
        """
        logger.info(f"CMD: [KeyProvisioning] ReadNonVolatileMemory(mem_id={mem_id})")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.NONE.tag,
            KeyProvOperation.READ_NON_VOLATILE.tag,
            mem_id,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def kp_set_user_key(self, key_type: int, key_data: bytes) -> bool:
        """Send the user key specified by key_type to bootloader for key provisioning.

        :param key_type: Type of the user key, see enumeration for details.
        :param key_data: Binary content of the user key.
        :return: True if key was successfully sent, False in case of any problem.
        """
        logger.info(
            f"CMD: [KeyProvisioning] SetUserKey(key_type={key_type}, " f"key_len={len(key_data)})"
        )
        data_chunks = self._split_data(data=key_data)
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.HAS_DATA_PHASE.tag,
            KeyProvOperation.SET_USER_KEY.tag,
            key_type,
            len(key_data),
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            return self._send_data(CommandTag.KEY_PROVISIONING, data_chunks)
        return False

    def kp_write_key_store(self, key_data: bytes) -> bool:
        """Key provisioning: Write key data into key store area.

        This method writes the provided key store binary content to the processor's
        key store area using the key provisioning protocol.

        :param key_data: Key store binary content to be written to processor.
        :return: True if operation succeeded, False otherwise.
        """
        logger.info(f"CMD: [KeyProvisioning] WriteKeyStore(key_len={len(key_data)})")
        data_chunks = self._split_data(data=key_data)
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING,
            CommandFlag.HAS_DATA_PHASE.tag,
            KeyProvOperation.WRITE_KEY_STORE.tag,
            0,
            len(key_data),
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            return self._send_data(CommandTag.KEY_PROVISIONING, data_chunks)
        return False

    def kp_read_key_store(self) -> Optional[bytes]:
        """Read key data from key store area.

        This method performs a key provisioning operation to retrieve key data
        stored in the device's key store area. The operation sends a READ_KEY_STORE
        command and processes the response to extract the key data.

        :return: Key data from key store area if successful, None if operation fails.
        """
        logger.info("CMD: [KeyProvisioning] ReadKeyStore")
        cmd_packet = CmdPacket(
            CommandTag.KEY_PROVISIONING, CommandFlag.NONE.tag, KeyProvOperation.READ_KEY_STORE.tag
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, KeyProvisioningResponse)
            return self._read_data(CommandTag.KEY_PROVISIONING, cmd_response.length)
        return None

    def load_image(
        self, data: bytes, progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> bool:
        """Load a boot image to the device.

        The method splits the boot image data into chunks and sends them to the device
        for loading. Progress can be tracked through an optional callback function.

        :param data: Boot image data to be loaded to the device.
        :param progress_callback: Optional callback function for progress updates, receives current
            and total progress values.
        :return: True if image loaded successfully, False if any problem occurred.
        """
        logger.info(f"CMD: LoadImage(length={len(data)})")
        data_chunks = self._split_data(data)
        # there's no command in this case
        self._status_code = StatusCode.SUCCESS.tag
        return self._send_data(CommandTag.NO_COMMAND, data_chunks, progress_callback)

    def tp_prove_genuinity(self, address: int, buffer_size: int) -> Optional[int]:
        """Start the process of proving genuinity.

        :param address: Address where to prove genuinity request (challenge) container.
        :param buffer_size: Maximum size of the response package (limit 0xFFFF).
        :raises McuBootError: Invalid input parameters.
        :return: Operation result if prove genuinity operation is successfully completed.
        """
        return self._tp_prove_genuinity(
            address=address, buffer_size=buffer_size, opcode=TrustProvOperation.PROVE_GENUINITY.tag
        )

    def tp_prove_genuinity_hybrid(self, address: int, buffer_size: int) -> Optional[int]:
        """Start the process of proving genuinity using hybrid mode.

        This method initiates a trust provisioning operation to prove the genuinity
        of the device using hybrid cryptographic approach.

        :param address: Address where to store the genuinity request (challenge) container.
        :param buffer_size: Maximum size of the response package (limit 0xFFFF).
        :raises McuBootError: Invalid input parameters.
        :return: Operation result code if successful, None otherwise.
        """
        return self._tp_prove_genuinity(
            address=address,
            buffer_size=buffer_size,
            opcode=TrustProvOperation.PROVE_GENUINITY_HYBRID.tag,
        )

    def _tp_prove_genuinity(self, address: int, buffer_size: int, opcode: int) -> Optional[int]:
        """Internal method to prove genuinity with configurable operation code.

        This method sends a trust provisioning command to prove device genuinity by processing
        a challenge container at the specified address and returning the response size.

        :param address: Address where to prove genuinity request (challenge) container is located.
        :param buffer_size: Maximum size of the response package (limit 0xFFFF).
        :param opcode: Operation code for trust provisioning.
        :raises McuBootError: Invalid input parameters or command response issues.
        :return: Response value indicating proof of genuinity result, or None if operation fails.
        """
        logger.info(
            f"CMD: [TrustProvisioning] ProveGenuinity(address={hex(address)}, "
            f"buffer_size={buffer_size})"
        )
        if buffer_size > 0xFFFF:
            raise McuBootError("buffer_size must be less than 0xFFFF")
        address_msb = (address >> 32) & 0xFFFF_FFFF
        address_lsb = address & 0xFFFF_FFFF
        sentinel_cmd = _tp_sentinel_frame(opcode, args=[address_msb, address_lsb, buffer_size])
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING, CommandFlag.NONE.tag, data=sentinel_cmd
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            assert isinstance(cmd_response, TrustProvisioningResponse)
            if len(cmd_response.values) > 0:
                return cmd_response.values[0]
            raise McuBootError("Command response doesn't contain value for PG response size")
        return None

    def tp_set_wrapped_data(self, address: int, stage: int = 0x4B, control: int = 1) -> bool:
        """Start the process of setting OEM data in TrustProvisioning flow.

        This method initiates the TrustProvisioning SetWrappedData operation to configure OEM data
        on the target device. The operation can use either a specified address or a container
        within the firmware.

        :param address: Address where the wrapped data container is located on target device
        :param stage: Stage of TrustProvisioning flow, defaults to 0x4B
        :param control: Control flag - 1 to use the address, 2 to use container within firmware,
                        defaults to 1
        :return: True if set_wrapped_data operation is successfully completed, False otherwise
        """
        logger.info(f"CMD: [TrustProvisioning] SetWrappedData(address={hex(address)})")
        if address == 0:
            control = 2

        address_msb = (address >> 32) & 0xFFFF_FFFF
        address_lsb = address & 0xFFFF_FFFF
        stage_control = control << 8 | stage
        sentinel_cmd = _tp_sentinel_frame(
            TrustProvOperation.ISP_SET_WRAPPED_DATA.tag,
            args=[stage_control, address_msb, address_lsb],
        )
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING, CommandFlag.NONE.tag, data=sentinel_cmd
        )
        cmd_response = self._process_cmd(cmd_packet)
        return cmd_response.status == StatusCode.SUCCESS

    def fuse_program(self, address: int, data: bytes, mem_id: int = 0) -> bool:
        """Program fuse memory with specified data.

        This method programs fuse memory at the given address with the provided data.
        The operation is performed through the MCU bootloader interface.

        :param address: Start address in fuse memory where programming begins.
        :param data: Binary data to be programmed into fuse memory.
        :param mem_id: Memory identifier for the target fuse memory (default: 0).
        :return: True if programming succeeded, False if any error occurred.
        """
        logger.info(
            f"CMD: FuseProgram(address=0x{address:08X}, length={len(data)}, mem_id={mem_id})"
        )
        data_chunks = self._split_data(data=data)
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(
            CommandTag.FUSE_PROGRAM, CommandFlag.HAS_DATA_PHASE.tag, address, len(data), mem_id
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:  # pragma: no cover
            # command is not supported in any device, thus we can't measure coverage
            return self._send_data(CommandTag.FUSE_PROGRAM, data_chunks)
        return False

    def fuse_read(self, address: int, length: int, mem_id: int = 0) -> Optional[bytes]:
        """Read fuse memory from the target device.

        This method reads data from the fuse memory at the specified address and length.
        The operation may fail if the fuse memory is not accessible or if invalid
        parameters are provided.

        :param address: Start address in fuse memory to read from.
        :param length: Number of bytes to read from fuse memory.
        :param mem_id: Memory identifier for fuse access, defaults to 0.
        :return: Data read from the fuse memory; None in case of a failure.
        """
        logger.info(f"CMD: ReadFuse(address=0x{address:08X}, length={length}, mem_id={mem_id})")
        mem_id = _clamp_down_memory_id(memory_id=mem_id)
        cmd_packet = CmdPacket(CommandTag.FUSE_READ, CommandFlag.NONE.tag, address, length, mem_id)
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:  # pragma: no cover
            # command is not supported in any device, thus we can't measure coverage
            assert isinstance(cmd_response, ReadMemoryResponse)
            return self._read_data(CommandTag.FUSE_READ, cmd_response.length)
        return None

    def update_life_cycle(self, life_cycle: int) -> bool:
        """Update device life cycle.

        This method sends a command to update the device's life cycle state to a new value.

        :param life_cycle: New life cycle value to set on the device.
        :return: True if the life cycle update was successful, False otherwise.
        """
        logger.info(f"CMD: UpdateLifeCycle (life cycle=0x{life_cycle:02X})")
        cmd_packet = CmdPacket(CommandTag.UPDATE_LIFE_CYCLE, CommandFlag.NONE.tag, life_cycle)
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def ele_message(
        self, cmdMsgAddr: int, cmdMsgCnt: int, respMsgAddr: int, respMsgCnt: int
    ) -> bool:
        """Send EdgeLock Enclave message.

        This method sends a command message to the EdgeLock Enclave and optionally receives a response.
        The command and response data are exchanged through RAM addresses.

        :param cmdMsgAddr: Address in RAM where the command message words are prepared.
        :param cmdMsgCnt: Count of 32-bit command words.
        :param respMsgAddr: Address in RAM where the response will be stored.
        :param respMsgCnt: Count of 32-bit response words.
        :return: True if the operation was successful, False otherwise.
        """
        logger.info(
            f"CMD: EleMessage Command (cmdMsgAddr=0x{cmdMsgAddr:08X}, cmdMsgCnt={cmdMsgCnt})"
        )
        if respMsgCnt:
            logger.info(
                f"CMD: EleMessage Response (respMsgAddr=0x{respMsgAddr:08X}, respMsgCnt={respMsgCnt})"
            )
        cmd_packet = CmdPacket(
            CommandTag.ELE_MESSAGE,
            CommandFlag.NONE.tag,
            0,  # reserved for future use as a sub command ID or anything else
            cmdMsgAddr,
            cmdMsgCnt,
            respMsgAddr,
            respMsgCnt,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def tp_hsm_gen_key(
        self,
        key_type: int,
        reserved: int,
        key_blob_output_addr: int,
        key_blob_output_size: int,
        ecdsa_puk_output_addr: int,
        ecdsa_puk_output_size: int,
    ) -> Optional[list[int]]:
        """Generate HSM keys for trust provisioning operations.

        This method generates common keys used in trust provisioning, including manufacturing
        firmware keys, encryption keys, signing keys, and customer master keys. The generated
        keys are written to specified output buffers.

        :param key_type: Type of key to generate (MFW_ISK, MFW_ENCK, GEN_SIGNK, GET_CUST_MK_SK).
        :param reserved: Reserved parameter, must be zero.
        :param key_blob_output_addr: Output buffer address where ROM writes the key blob.
        :param key_blob_output_size: Size of the key blob output buffer in bytes.
        :param ecdsa_puk_output_addr: Output buffer address where ROM writes the public key.
        :param ecdsa_puk_output_size: Size of the public key output buffer in bytes.
        :return: List containing byte count of the key blob and public key from device,
            None if operation fails.
        """
        logger.info("CMD: [TrustProvisioning] OEM generate common keys")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_GEN_KEY.tag,
            key_type,
            reserved,
            key_blob_output_addr,
            key_blob_output_size,
            ecdsa_puk_output_addr,
            ecdsa_puk_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def tp_oem_gen_master_share(
        self,
        oem_share_input_addr: int,
        oem_share_input_size: int,
        oem_enc_share_output_addr: int,
        oem_enc_share_output_size: int,
        oem_enc_master_share_output_addr: int,
        oem_enc_master_share_output_size: int,
        oem_cust_cert_puk_output_addr: int,
        oem_cust_cert_puk_output_size: int,
    ) -> Optional[list[int]]:
        """Generate OEM master share for trust provisioning.

        Takes the entropy seed provided by the OEM as input and generates encrypted shares
        and customer certificate public key through the trust provisioning operation.

        :param oem_share_input_addr: The input buffer address where the OEM Share
            (entropy seed) is located.
        :param oem_share_input_size: The byte count of the OEM Share.
        :param oem_enc_share_output_addr: The output buffer address where ROM writes
            the Encrypted OEM Share.
        :param oem_enc_share_output_size: The output buffer size in bytes.
        :param oem_enc_master_share_output_addr: The output buffer address where ROM
            writes the Encrypted OEM Master Share.
        :param oem_enc_master_share_output_size: The output buffer size in bytes.
        :param oem_cust_cert_puk_output_addr: The output buffer address where ROM
            writes the OEM Customer Certificate Public Key.
        :param oem_cust_cert_puk_output_size: The output buffer size in bytes.
        :return: Sizes of two encrypted blobs (the Encrypted OEM Share and the
            Encrypted OEM Master Share) and a public key (the OEM Customer Certificate
            Public Key), or None if operation fails.
        """
        logger.info("CMD: [TrustProvisioning] OEM generate master share")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.OEM_GEN_MASTER_SHARE.tag,
            oem_share_input_addr,
            oem_share_input_size,
            oem_enc_share_output_addr,
            oem_enc_share_output_size,
            oem_enc_master_share_output_addr,
            oem_enc_master_share_output_size,
            oem_cust_cert_puk_output_addr,
            oem_cust_cert_puk_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def tp_oem_set_master_share(
        self,
        oem_share_input_addr: int,
        oem_share_input_size: int,
        oem_enc_master_share_input_addr: int,
        oem_enc_master_share_input_size: int,
    ) -> bool:
        """Set OEM master share for trust provisioning.

        Takes the entropy seed and the Encrypted OEM Master Share to configure
        the trust provisioning process.

        :param oem_share_input_addr: The input buffer address where the OEM Share
            (entropy seed) is located.
        :param oem_share_input_size: The byte count of the OEM Share.
        :param oem_enc_master_share_input_addr: The input buffer address where the
            Encrypted OEM Master Share is located.
        :param oem_enc_master_share_input_size: The byte count of the Encrypted OEM
            Master Share.
        :return: True if operation succeeded, False otherwise.
        """
        logger.info(
            "CMD: [TrustProvisioning] Takes the entropy seed and the Encrypted OEM Master Share."
        )
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.OEM_SET_MASTER_SHARE.tag,
            oem_share_input_addr,
            oem_share_input_size,
            oem_enc_master_share_input_addr,
            oem_enc_master_share_input_size,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def tp_oem_get_cust_cert_dice_puk(
        self,
        oem_rkth_input_addr: int,
        oem_rkth_input_size: int,
        oem_cust_cert_dice_puk_output_addr: int,
        oem_cust_cert_dice_puk_output_size: int,
        mldsa: bool = False,
    ) -> Optional[int]:
        """Get OEM customer certificate DICE public key.

        Creates the initial DICE CA keys by processing OEM Root Key Table Hash (RKTH) input
        and generating the corresponding OEM Customer Certificate Public Key for DICE.

        :param oem_rkth_input_addr: Input buffer address where the OEM RKTH is located.
        :param oem_rkth_input_size: Byte count of the OEM RKTH.
        :param oem_cust_cert_dice_puk_output_addr: Output buffer address where ROM writes the
            OEM Customer Certificate Public Key for DICE.
        :param oem_cust_cert_dice_puk_output_size: Output buffer size in bytes.
        :param mldsa: Flag to indicate MLDSA operation, defaults to False.
        :return: Byte count of the OEM Customer Certificate Public Key for DICE, or None if
            operation fails.
        """
        logger.info("CMD: [TrustProvisioning] Creates the initial DICE CA keys")
        operation_tag = (
            TrustProvOperation.OEM_GET_CUST_DICE_RESPONSE.tag
            if mldsa
            else TrustProvOperation.OEM_GET_CUST_CERT_DICE_PUK.tag
        )
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            operation_tag,
            oem_rkth_input_addr,
            oem_rkth_input_size,
            oem_cust_cert_dice_puk_output_addr,
            oem_cust_cert_dice_puk_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def tp_oem_get_cust_dice_response(
        self,
        challenge_addr: int,
        challenge_size: int,
        response_addr: int,
        response_size: int,
    ) -> Optional[int]:
        """Create DICE response for given challenge.

        This method generates a Device Identifier Composition Engine (DICE) response
        based on the provided challenge data through the Trust Provisioning interface.

        :param challenge_addr: The input buffer address where the challenge is located.
        :param challenge_size: The byte count of the challenge.
        :param response_addr: The output buffer address where ROM/FW writes the response.
        :param response_size: The byte count of the response.
        :return: The byte count of the DICE response, or None if operation failed.
        """
        logger.info("CMD: [TrustProvisioning] Creates DICE response for given challenge")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.OEM_GET_CUST_DICE_RESPONSE.tag,
            challenge_addr,
            challenge_size,
            response_addr,
            response_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def tp_hsm_store_key(
        self,
        key_type: int,
        key_property: int,
        key_input_addr: int,
        key_input_size: int,
        key_blob_output_addr: int,
        key_blob_output_size: int,
    ) -> Optional[list[int]]:
        """Trust provisioning: Store OEM common keys.

        This method stores OEM common keys using the trust provisioning HSM functionality.
        The key is stored as a blob in the specified output buffer location.

        :param key_type: Key type to store (CKDFK, HKDFK, HMACK, CMACK, AESK, KUOK)
        :param key_property: Key properties - Bit 0: Key Size (0=128bit, 1=256bit),
            Bits 30-31: CSS protection mode
        :param key_input_addr: Input buffer address where the key is located
        :param key_input_size: Size of the key in bytes
        :param key_blob_output_addr: Output buffer address for the key blob
        :param key_blob_output_size: Output buffer size in bytes
        :return: Key blob header and byte count (header excluded) on success, None on failure
        """
        logger.info("CMD: [TrustProvisioning] OEM generate common keys")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_STORE_KEY.tag,
            key_type,
            key_property,
            key_input_addr,
            key_input_size,
            key_blob_output_addr,
            key_blob_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def tp_hsm_enc_blk(
        self,
        mfg_cust_mk_sk_0_blob_input_addr: int,
        mfg_cust_mk_sk_0_blob_input_size: int,
        kek_id: int,
        sb3_header_input_addr: int,
        sb3_header_input_size: int,
        block_num: int,
        block_data_addr: int,
        block_data_size: int,
    ) -> bool:
        """Trust provisioning: Encrypt the given SB3 data block.

        This method encrypts a Secure Binary 3 (SB3) data block using HSM encryption with the
        provided CKDF Master Key Blob and encryption parameters.

        :param mfg_cust_mk_sk_0_blob_input_addr: The input buffer address where the CKDF
            Master Key Blob locates at.
        :param mfg_cust_mk_sk_0_blob_input_size: The byte count of the CKDF Master Key Blob.
        :param kek_id: The CKDF Master Key Encryption Key ID (0x10: NXP_CUST_KEK_INT_SK,
            0x11: NXP_CUST_KEK_EXT_SK).
        :param sb3_header_input_addr: The input buffer address where the SB3 Header (block0)
            locates at.
        :param sb3_header_input_size: The byte count of the SB3 Header.
        :param block_num: The index of the block. Due to SB3 Header (block 0) is always
            unencrypted, the index starts from block1.
        :param block_data_addr: The buffer address where the SB3 data block locates at.
        :param block_data_size: The byte count of the SB3 data block.
        :return: True if encryption was successful, False otherwise.
        """
        logger.info("CMD: [TrustProvisioning] Encrypt the given SB3 data block")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_ENC_BLOCK.tag,
            mfg_cust_mk_sk_0_blob_input_addr,
            mfg_cust_mk_sk_0_blob_input_size,
            kek_id,
            sb3_header_input_addr,
            sb3_header_input_size,
            block_num,
            block_data_addr,
            block_data_size,
        )
        return self._process_cmd(cmd_packet).status == StatusCode.SUCCESS

    def tp_hsm_enc_sign(
        self,
        key_blob_input_addr: int,
        key_blob_input_size: int,
        block_data_input_addr: int,
        block_data_input_size: int,
        signature_output_addr: int,
        signature_output_size: int,
    ) -> Optional[int]:
        """Sign data using HSM encryption and signing operation.

        This method performs Trust Provisioning HSM encryption and signing operation on the provided
        data block using the specified key blob, writing the resulting signature to the output buffer.

        :param key_blob_input_addr: Input buffer address where signing key blob is located.
        :param key_blob_input_size: Size of the signing key blob in bytes.
        :param block_data_input_addr: Input buffer address where the data to be signed is located.
        :param block_data_input_size: Size of the data to be signed in bytes.
        :param signature_output_addr: Output buffer address where ROM writes the signature.
        :param signature_output_size: Size of the output buffer in bytes.
        :return: Signature size in bytes if successful, None if operation fails.
        """
        logger.info("CMD: [TrustProvisioning] HSM ENC SIGN")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvOperation.HSM_ENC_SIGN.tag,
            key_blob_input_addr,
            key_blob_input_size,
            block_data_input_addr,
            block_data_input_size,
            signature_output_addr,
            signature_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def wpc_get_id(
        self,
        wpc_id_blob_addr: int,
        wpc_id_blob_size: int,
    ) -> Optional[int]:
        """Command used for harvesting device ID blob.

        The method retrieves the Wireless Power Consortium (WPC) device identification
        blob from the target device through trust provisioning interface.

        :param wpc_id_blob_addr: Buffer address where the WPC ID blob will be stored.
        :param wpc_id_blob_size: Size of the buffer allocated for the WPC ID blob.
        :return: Device ID value if successful, None if command fails or returns invalid response.
        """
        logger.info("CMD: [TrustProvisioning] WPC GET ID")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.WPC_GET_ID.tag,
            wpc_id_blob_addr,
            wpc_id_blob_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def nxp_get_id(
        self,
        id_blob_addr: int,
        id_blob_size: int,
    ) -> Optional[int]:
        """Harvest device ID blob during wafer test as part of RTS flow.

        This command retrieves the device ID blob from the specified memory location
        according to the Round-trip trust provisioning specification.

        :param id_blob_addr: Address of ID blob in device memory.
        :param id_blob_size: Size of the ID blob buffer in bytes.
        :return: First value from trust provisioning response if successful, None otherwise.
        """
        logger.info("CMD: [TrustProvisioning] NXP GET ID")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.NXP_GET_ID.tag,
            id_blob_addr,
            id_blob_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def wpc_insert_cert(
        self,
        wpc_cert_addr: int,
        wpc_cert_len: int,
        ec_id_offset: int,
        wpc_puk_offset: int,
    ) -> Optional[int]:
        """Insert WPC certificate for validation before writing to flash.

        This command extracts ECID and WPC PUK from the certificate and validates both
        components. Returns success if validation passes, otherwise returns failure.

        :param wpc_cert_addr: Address of the certificate to be inserted.
        :param wpc_cert_len: Length of the certificate in bytes.
        :param ec_id_offset: Offset to the 72-bit ECID within the certificate.
        :param wpc_puk_offset: Offset to the WPC PUK from the beginning of the certificate.
        :return: 0 if validation successful, None if validation failed.
        """
        logger.info("CMD: [TrustProvisioning] WPC INSERT CERT")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.WPC_INSERT_CERT.tag,
            wpc_cert_addr,
            wpc_cert_len,
            ec_id_offset,
            wpc_puk_offset,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if cmd_response.status == StatusCode.SUCCESS:
            return 0
        return None

    def wpc_sign_csr(
        self,
        csr_tbs_addr: int,
        csr_tbs_len: int,
        signature_addr: int,
        signature_len: int,
    ) -> Optional[int]:
        """Sign CSR data using the TBS (To Be Signed) portion.

        This command signs Certificate Signing Request data and stores the resulting signature
        at the specified memory location.

        :param csr_tbs_addr: Address of CSR-TBS data in memory.
        :param csr_tbs_len: Length in bytes of CSR-TBS data.
        :param signature_addr: Address where to store the generated signature.
        :param signature_len: Expected length of the signature in bytes.
        :return: Actual signature length if successful, None otherwise.
        """
        logger.info("CMD: [TrustProvisioning] WPC SIGN CSR-TBS DATA")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvWpc.WPC_SIGN_CSR.tag,
            csr_tbs_addr,
            csr_tbs_len,
            signature_addr,
            signature_len,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def dsc_hsm_create_session(
        self,
        oem_seed_input_addr: int,
        oem_seed_input_size: int,
        oem_share_output_addr: int,
        oem_share_output_size: int,
    ) -> Optional[int]:
        """Create DSC HSM session for trust provisioning.

        Command used by OEM to provide its share to create the initial trust provisioning keys.

        :param oem_seed_input_addr: Address of 128-bit entropy seed value provided by the OEM.
        :param oem_seed_input_size: OEM seed size in bytes.
        :param oem_share_output_addr: Address for 128-bit encrypted token output.
        :param oem_share_output_size: Output buffer size in bytes.
        :return: Session value if successful, None otherwise.
        """
        logger.info("CMD: [TrustProvisioning] DSC HSM CREATE SESSION")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvDevHsmDsc.DSC_HSM_CREATE_SESSION.tag,
            oem_seed_input_addr,
            oem_seed_input_size,
            oem_share_output_addr,
            oem_share_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def dsc_hsm_enc_blk(
        self,
        sbx_header_input_addr: int,
        sbx_header_input_size: int,
        block_num: int,
        block_data_addr: int,
        block_data_size: int,
    ) -> Optional[int]:
        """Command used to encrypt the given block sliced by the nxpimage.

        This command is only supported after issuance of dsc_hsm_create_session.

        :param sbx_header_input_addr: SBx header containing file size, Firmware version and
            Timestamp data. Except for hash digest of block 0, all other fields should be valid.
        :param sbx_header_input_size: Size of the header in bytes.
        :param block_num: Number of block to encrypt.
        :param block_data_addr: Address of data block to encrypt.
        :param block_data_size: Size of data block in bytes.
        :return: Response value from trust provisioning operation, None if operation failed.
        """
        logger.info("CMD: [TrustProvisioning] DSC HSM ENC BLK")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvDevHsmDsc.DSC_HSM_ENC_BLK.tag,
            sbx_header_input_addr,
            sbx_header_input_size,
            block_num,
            block_data_addr,
            block_data_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def dsc_hsm_enc_sign(
        self,
        block_data_input_addr: int,
        block_data_input_size: int,
        signature_output_addr: int,
        signature_output_size: int,
    ) -> Optional[int]:
        """Sign data buffer using DSC HSM encryption.

        This command is only supported after issuance of dsc_hsm_create_session.

        :param block_data_input_addr: Address of data buffer to be signed.
        :param block_data_input_size: Size of data buffer in bytes.
        :param signature_output_addr: Address to output signature data.
        :param signature_output_size: Size of the output signature data in bytes.
        :return: Response value from trust provisioning operation, None if operation failed.
        """
        logger.info("CMD: [TrustProvisioning] DSC HSM ENC SIGN")
        cmd_packet = CmdPacket(
            CommandTag.TRUST_PROVISIONING,
            CommandFlag.NONE.tag,
            TrustProvDevHsmDsc.DSC_HSM_ENC_SIGN.tag,
            block_data_input_addr,
            block_data_input_size,
            signature_output_addr,
            signature_output_size,
        )
        cmd_response = self._process_cmd(cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def el2go_get_version(self) -> Optional[list[int]]:
        """Get version of the EL2GO Provisioning FW.

        This method retrieves the firmware version information from the EL2GO (EdgeLock 2GO)
        provisioning system by sending a version query command and processing the response.

        :return: List of version integers if successful, None if the command fails or returns
            an unexpected response type.
        """
        logger.info("CMD: Getting FW version")
        cmd_packet = CmdPacket(
            CommandTag.EL2GO, CommandFlag.NONE.tag, EL2GOCommandGroup.EL2GO_GET_FW_VERSION.tag
        )
        cmd_response = self._process_cmd(cmd_packet=cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values
        return None

    def el2go_close_device(self, address: int, dry_run: bool = False) -> Optional[int]:
        """Close device using EL2GO Provisioning FW.

        This command finalizes the device provisioning process by closing the device
        through the EL2GO (EdgeLock 2GO) provisioning firmware.

        :param address: Target device address for the close operation.
        :param dry_run: If True, performs a simulation without actual device changes.
        :return: Response value from the trust provisioning operation, or None if operation failed.
        """
        logger.info("CMD: Device-based Close device")
        cmd_packet = CmdPacket(
            CommandTag.EL2GO,
            CommandFlag.NONE.tag,
            EL2GOCommandGroup.EL2GO_CLOSE_DEVICE.tag,
            address,
            dry_run,
        )
        cmd_response = self._process_cmd(cmd_packet=cmd_packet)
        if isinstance(cmd_response, TrustProvisioningResponse):
            return cmd_response.values[0]
        return None

    def el2go_batch_tp(
        self,
        data_address: int,
        report_address: int = 0xFFFF_FFFF,
        dry_run: bool = False,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> tuple[Optional[int], Optional[bytes]]:
        """Perform EL2GO batch trust provisioning operation.

        Executes product-based trust provisioning using secure objects stored at the specified
        address in target memory. Optionally stores provisioning report and supports dry-run mode
        for validation without actual provisioning.

        :param data_address: Memory address where secure objects are stored in target device.
        :param report_address: Memory address to store provisioning report, defaults to
            0xFFFF_FFFF (no report storage).
        :param dry_run: Execute validation only without actual provisioning, defaults to False.
        :param progress_callback: Optional callback function for progress updates during data
            transfer operations.
        :return: Tuple containing status code and provisioning report data if successful,
            (None, None) if operation failed.
        """
        logger.info("CMD: Batch Trust Provisioning")
        cmd_packet = CmdPacket(
            CommandTag.EL2GO,
            CommandFlag.NONE.tag,
            EL2GOCommandGroup.EL2GO_BATCH_TP.tag,
            data_address,
            dry_run,
            report_address,
        )
        cmd_response = self._process_cmd(cmd_packet=cmd_packet)

        if cmd_response.status != StatusCode.SUCCESS:
            return None, None

        assert isinstance(cmd_response, TrustProvisioningResponse)

        status_code = cmd_response.values[0] if cmd_response.values else None
        if status_code != StatusCode.EL2GO_PROV_SUCCESS.tag:
            return status_code, None

        # no data phase
        if cmd_response.header.flags != CommandFlag.HAS_DATA_PHASE.tag:
            return status_code, cmd_response.get_payload_data(offset=1)

        # data is coming in data phase
        if len(cmd_response.values) == 2:
            data = self._read_data(CommandTag.EL2GO, cmd_response.values[1], progress_callback)
            return status_code, data

        # Return existing payload data present the response
        return status_code, cmd_response.get_payload_data(offset=1)


####################
# Helper functions #
####################


def _tp_sentinel_frame(command: int, args: list[int], tag: int = 0x17, version: int = 0) -> bytes:
    """Prepare frame used by sentinel.

    Creates a binary frame structure for sentinel communication with command,
    arguments, and metadata packed in little-endian format.

    :param command: Command identifier for the sentinel operation.
    :param args: List of integer arguments to be packed into the frame.
    :param tag: Frame tag identifier, defaults to 0x17.
    :param version: Frame version number, defaults to 0.
    :return: Binary frame data ready for sentinel communication.
    """
    data = struct.pack("<4B", command, len(args), version, tag)
    for item in args:
        data += struct.pack("<I", item)
    return data


def _clamp_down_memory_id(memory_id: int) -> int:
    """Clamp down memory ID to zero for mapped external memory access.

    This method validates the memory ID and returns 0 for mapped external memory
    (memory IDs 1-255) while preserving other values. A warning is logged when
    clamping occurs to inform about the automatic adjustment.

    :param memory_id: Memory identifier to be validated and potentially clamped.
    :return: Clamped memory ID (0 for mapped external memory, original value otherwise).
    """
    if memory_id > 255 or memory_id == 0:
        return memory_id
    logger.warning("Note: memoryId is not required when accessing mapped external memory")
    return 0
