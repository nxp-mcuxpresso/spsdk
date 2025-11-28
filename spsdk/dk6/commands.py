#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""DK6 device communication commands and responses.

This module provides command and response structures for communicating with DK6 devices,
including memory operations, device identification, and status management. It defines
command packets, response parsing, and various memory access utilities for the DK6
protocol implementation.
"""

from struct import unpack_from
from typing import Optional, Type, Union

from spsdk.utils.spsdk_enum import SpsdkEnum


class StatusCode(SpsdkEnum):
    """DK6 Command Status Codes enumeration.

    This enumeration defines all possible status codes returned by DK6 commands,
    including success status and various error conditions for memory operations,
    authentication, and communication failures.
    """

    OK = (0x00, "OK", "Success")
    MEMORY_INVALID_MODE = (0xEF, "MEMORY_INVALID_MODE", "Memory invalid mode")
    MEMORY_BAD_STATE = (0xF0, "MEMORY_BAD_STATE", "Memory bad state")
    MEMORY_TOO_LONG = (0xF1, "MEMORY_TOO_LONG", "Memory too long")
    MEMORY_OUT_OF_RANGE = (0xF2, "MEMORY_OUT_OF_RANGE", "Memory out of range")
    MEMORY_ACCESS_INVALID = (0xF3, "MEMORY_ACCESS_INVALID", "Memory access invalid")
    MEMORY_NOT_SUPPORTED = (0xF4, "MEMORY_NOT_SUPPORTED", "Memory not supported")
    MEMORY_INVALID = (0xF5, "MEMORY_INVALID", "Memory invalid")
    NO_RESPONSE = (0xF6, "NO_RESPONSE", "No response")
    AUTH_ERROR = (0xF7, "AUTH_ERROR", "Not authorized")
    TEST_ERROR = (0xF8, "TEST_ERROR", "Test Error")
    READ_FAIL = (0xF9, "READ_FAIL", "Read fail")
    USER_INTERRUPT = (0xFA, "USER_INTERRUPT", "User interrupt")
    ASSERT_FAIL = (0xFB, "ASSERT_FAIL", "Assertion fail")
    CRC_ERROR = (0xFC, "CRC_ERROR", "CRC Error")
    INVALID_RESPONSE = (0xFD, "INVALID_RESPONSE", "Invalid response")
    WRITE_FAIL = (0xFE, "WRITE_FAIL", "Write fail")
    NOT_SUPPORTED = (0xFF, "NOT_SUPPORTED", "Not supported")


class ResponseTag(SpsdkEnum):
    """DK6 Response Tag Enumeration.

    Enumeration of response tags used in DK6 protocol communication to identify
    different types of responses from the target device including memory operations,
    chip identification, and ISP unlock responses.
    """

    RESET = (0x15, "ResetResponse", "Reset Response")
    EXECUTE = (0x22, "ExecuteResponse", "Execute Response")
    SET_BAUD = (0x28, "SetBaudResponse", "Set Baud Response")
    GET_CHIPID = (0x33, "GetChipIdResponse", "Get Chip ID Response")
    MEM_OPEN = (0x41, "MemOpenResponse", "Memory Open Response")
    MEM_ERASE = (0x43, "MemEraseResponse", "Memory Erase Response")
    MEM_BLANK_CHECK = (0x45, "MemBlankCheckResponse", "Memory Blank Check Response")
    MEM_READ = (0x47, "MemReadResponse", "Memory Read Response")
    MEM_WRITE = (0x49, "MemoryWriteResponse", "Memory Write Response")
    MEM_CLOSE = (0x4B, "MemoryCloseResponse", "Memory Close Response")
    MEM_GET_INFO = (0x4D, "MemoryGetInfoResponse", "Memory Get Info Response")
    UNLOCK_ISP = (0x4F, "UnlockISPResponse", "Unlock ISP Response")


class CommandTag(SpsdkEnum):
    """DK6 command enumeration for device communication protocol.

    This enumeration defines all supported commands for DK6 device communication,
    including memory operations, device control, and ISP functionality. Each command
    contains the command code, internal name, and human-readable description.
    """

    RESET = (0x14, "ResetCommand", "Reset Command")
    EXECUTE = (0x21, "ExecuteCommand", "Execute Command")
    SET_BAUD = (0x27, "SetBaudCommand", "Set Baud Command")
    GET_CHIPID = (0x32, "GetChipIdCommand", "Get Chip ID Command")
    MEM_OPEN = (0x40, "MemOpenCommand", "Memory Open Command")
    MEM_ERASE = (0x42, "MemEraseCommand", "Memory Erase Command")
    MEM_BLANK_CHECK = (0x44, "MemBlankCheckCommand", "Memory Blank Check Command")
    MEM_READ = (0x46, "MemReadCommand", "Memory Read Command")
    MEM_WRITE = (0x48, "MemoryWriteCommand", "Memory Write Command")
    MEM_CLOSE = (0x4A, "MemoryCloseCommand", "Memory Close Command")
    MEM_GET_INFO = (0x4C, "MemoryGetInfoCommand", "Memory Get Info Command")
    UNLOCK_ISP = (0x4E, "UnlockISPCommand", "Unlock ISP Command")


class MemoryId(SpsdkEnum):
    """DK6 Memory ID enumeration.

    This enumeration defines the available memory types and their corresponding
    identifiers for DK6 device operations including flash programming, configuration
    access, and memory management operations.
    """

    FLASH = (0x00, "FLASH")
    PSECT = (0x01, "PSECT")
    pFLASH = (0x02, "pFLASH")
    Config = (0x03, "Config")
    EFUSE = (0x04, "EFUSE")
    ROM = (0x05, "ROM")
    RAM0 = (0x06, "RAM0")
    RAM1 = (0x07, "RAM1")


class MemoryType(SpsdkEnum):
    """DK6 Memory Types enumeration.

    This enumeration defines the available memory types for DK6 operations,
    including ROM, FLASH, RAM, and EFUSE memory types with their corresponding
    identifiers and descriptions.
    """

    ROM = (0x00, "ROM", "Read only memory")
    FLASH = (0x01, "FLASH", "FLASH memory")
    RAM = (0x02, "RAM", "RAM")
    EFUSE = (0x05, "EFUSE (OTP)", "EFUSE (OTP)")


class MemoryAccessValues(SpsdkEnum):
    """DK6 Memory Access Permission Values.

    Enumeration defining memory access permission values for DK6 operations.
    Each value represents a specific type of memory access that can be enabled
    or disabled for security and operational control.
    """

    READ = (0x00, "Read Enabled")
    WRITE = (0x01, "Write Enabled")
    ERASE = (0x02, "Erase Enabled")
    ERASE_ALL = (0x03, "Erase All Enabled")
    BLANK_CHECK_ENABLED = (0x04, "Blank Check Enabled")
    ALL = (0x0F, "All is available")


class CmdPacket:
    """DK6 command packet representation.

    This class encapsulates command data for DK6 operations, providing methods
    for packet creation, comparison, serialization, and debugging information.
    """

    def __init__(self, data: bytes) -> None:
        """Initialize the Command Packet object.

        :param data: Command data bytes to be stored in the packet.
        """
        self.data = data

    def __eq__(self, obj: object) -> bool:
        """Check equality between two CmdPacket objects.

        Compares this CmdPacket instance with another object by checking if the other object
        is also a CmdPacket instance and has identical attributes.

        :param obj: Object to compare with this CmdPacket instance.
        :return: True if objects are equal CmdPacket instances with same attributes, False otherwise.
        """
        return isinstance(obj, CmdPacket) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        """Check if two objects are not equal.

        This method implements the inequality comparison by negating the equality comparison.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    def __str__(self) -> str:
        """Return string representation of the object.

        The method provides a formatted string representation by wrapping the info() method
        output in angle brackets for better readability.

        :return: String representation in format "<info_content>".
        """
        return "<" + self.info() + ">"

    def info(self) -> str:
        """Get object info.

        Returns a string representation of the CMDPacket object showing its data bytes in hexadecimal format.

        :return: String representation in format "CMDPacket[XX, XX, ...]" where XX are hex bytes.
        """
        return "CMDPacket[" + ", ".join(f"{b:02X}" for b in self.data) + "]"

    def export(self) -> Optional[bytes]:
        """Export CmdPacket into bytes.

        :return: Exported object data as bytes, or None if no data is available.
        """
        return self.data


class CmdResponse:
    """DK6 command response handler.

    This class represents and manages DK6 command responses, providing parsing
    and formatting capabilities for response data including status codes and
    raw message content.

    :cvar MSG_OFFSET: Offset position for message data in response buffer.
    """

    MSG_OFFSET = 1

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param cmd_type: Command type identifier
        :param raw_data: Raw response data as bytes
        :raises AssertionError: If raw_data is not bytes or bytearray type
        """
        assert isinstance(raw_data, (bytes, bytearray))
        self.type = cmd_type
        self.status = raw_data[0]
        self.raw_data = raw_data

    def __eq__(self, obj: object) -> bool:
        """Check equality of two CmdResponse objects.

        Compares this CmdResponse instance with another object by checking if the other object
        is also a CmdResponse instance and has identical attributes.

        :param obj: Object to compare with this CmdResponse instance.
        :return: True if objects are equal CmdResponse instances with same attributes, False otherwise.
        """
        return isinstance(obj, CmdResponse) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        """Check if this object is not equal to another object.

        This method implements the inequality comparison operator by negating the equality check.

        :param obj: Object to compare with this instance.
        :return: True if objects are not equal, False if they are equal.
        """
        return not self.__eq__(obj)

    def __str__(self) -> str:
        """Return string representation of the object.

        :return: String representation in format "<info()>".
        """
        return "<" + self.info() + ">"

    def info(self) -> str:
        """Get object info.

        Returns a formatted string containing the object's status, type, and raw data
        in hexadecimal format.

        :return: Formatted string with status, type and raw data in hex format.
        """
        return (
            f"Status=0x{self.status:02X}"
            + f"Type=0x{self.type:02X}"
            + " ["
            + ", ".join(f"{b:02X}" for b in self.raw_data)
            + "]"
        )

    def _get_status_label(self) -> str:
        """Get human-readable label for the status code.

        Converts the status code to a readable string representation. If the status code
        is recognized by StatusCode enum, returns its label. Otherwise, returns a formatted
        string with the hexadecimal value.

        :return: Human-readable status label or formatted unknown status string.
        """
        return (
            StatusCode.get_label(self.status)
            if StatusCode.contains(self.status)
            else f"Unknown[0x{self.status:08X}]"
        )


class GenericResponse(CmdResponse):
    """DK6 generic response format class.

    This class represents a standard response format for DK6 commands, providing
    a generic structure for handling command responses with status information
    and formatted output capabilities.
    """

    def info(self) -> str:
        """Get object info.

        Returns a formatted string containing the object's tag and status information.

        :return: Formatted string with tag and status details.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class IspUnlockResponse(CmdResponse):
    """ISP Unlock response format class.

    This class represents the response received from an ISP (In-System Programming) unlock command,
    providing authentication status and response details for secure provisioning operations.
    """

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param cmd_type: Type of the command
        :param raw_data: Response data
        """
        super().__init__(cmd_type, raw_data)
        self.authenticated = self.status == StatusCode.OK

    def info(self) -> str:
        """Get object info.

        Returns a formatted string containing the object's tag, status, and authentication state.

        :return: Formatted string with tag, status, and authenticated information.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Authenticated={self.authenticated}"


class GetChipIdResponse(CmdResponse):
    """DK6 command response for chip identification operations.

    This class handles the response data from chip ID retrieval commands,
    parsing the chip ID and version information from the raw response data.

    :cvar FORMAT: Binary format string for unpacking chip ID and version data.
    """

    FORMAT = "<II"

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Once response object.

        Creates a response object for Flash-Read-Once command with chip identification data.
        When status is OK, extracts chip ID and version from the raw response data.

        :param cmd_type: Command type identifier for the response
        :param raw_data: Raw response data containing chip information
        """
        super().__init__(cmd_type, raw_data)
        if self.status == StatusCode.OK:
            (self.chip_id, self.chip_version) = unpack_from(self.FORMAT, raw_data, self.MSG_OFFSET)

    def info(self) -> str:
        """Get object information as formatted string.

        Returns a formatted string containing the response tag, status, and optionally
        chip ID and version information when the status is OK.

        :return: Formatted string with object information including tag, status, and chip details.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        if self.status == StatusCode.OK:
            return f"Tag={tag}, Status={status}, ChipID={hex(self.chip_id)}, ChipVersion={hex(self.chip_version)}"
        return f"Tag={tag}, Status={status}"


class MemGetInfoResponse(CmdResponse):
    """Memory get info response handler for DK6 bootloader commands.

    This class processes and parses responses from memory get info commands,
    extracting memory properties such as base address, length, sector size,
    memory type, and access permissions when the command executes successfully.

    :cvar FORMAT: Binary format string for unpacking response data.
    :cvar MEM_NAME_OFFSET: Byte offset where memory name starts in response.
    """

    FORMAT = "<BIIIBB"
    MEM_NAME_OFFSET = 15

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Once response object.

        Parses the raw response data to extract memory information including
        memory name, ID, base address, length, sector size, type, and access permissions.

        :param cmd_type: Command type identifier for the response
        :param raw_data: Raw response data containing memory information
        :raises SPSDKError: If response parsing fails or data is corrupted
        """
        super().__init__(cmd_type, raw_data)
        if self.status == StatusCode.OK:
            self.mem_name = raw_data[self.MEM_NAME_OFFSET :].decode("ascii")
            (
                self.memory_id,
                self.base_addr,
                self.length,
                self.sector_size,
                self.mem_type,
                self.access,
            ) = unpack_from(self.FORMAT, raw_data, self.MSG_OFFSET)

    def info(self) -> str:
        """Get object information as formatted string.

        Returns detailed memory information including tag, status, memory name, ID, base address,
        length, sector size, memory type, and access permissions when status is OK. For non-OK
        status, returns only tag and status information.

        :return: Formatted string containing object information details.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        if self.status == StatusCode.OK:
            memory_id = MemoryId.get_label(self.memory_id)
            mem_type = MemoryType.get_label(self.mem_type)
            access = MemoryAccessValues.get_label(self.access)
            return (
                f"Tag={tag}, Status={status}, MemName = {self.mem_name}, "
                + f"MemoryId={memory_id}, BaseAddress={hex(self.base_addr)}, "
                + f"Length={hex(self.length)}, SectorSize={hex(self.sector_size)}, "
                + f"MemoryType={mem_type}, Access={access}"
            )
        return f"Tag={tag}, Status={status}"


class MemOpenResponse(CmdResponse):
    """Memory open response handler for DK6 commands.

    This class processes and parses responses from memory open operations,
    extracting the memory handle when the operation is successful and providing
    formatted information about the response status.

    :cvar FORMAT: Binary format string for unpacking response data.
    """

    FORMAT = "<B"

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param cmd_type: Type of the command
        :param raw_data: Response data
        :raises SPSDKError: If command processing fails
        """
        super().__init__(cmd_type, raw_data)
        if self.status == StatusCode.OK:
            self.handle = unpack_from(self.FORMAT, raw_data, self.MSG_OFFSET)

    def info(self) -> str:
        """Get object information as formatted string.

        Returns a formatted string containing the response tag, status, and optionally
        the handle if the status is OK.

        :return: Formatted string with object information including tag, status and handle.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        if self.status == StatusCode.OK:
            return f"Tag={tag}, Status={status}, Handle={self.handle}"
        return f"Tag={tag}, Status={status}"


class MemReadResponse(CmdResponse):
    """Memory read response handler for DK6 commands.

    This class processes and manages response data from memory read operations,
    parsing the raw response data and extracting the actual memory content
    when the operation is successful.
    """

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param cmd_type: Command type identifier
        :param raw_data: Raw response data bytes
        """
        super().__init__(cmd_type, raw_data)
        self.data = b""
        if self.status == StatusCode.OK:
            self.data = self.raw_data[self.MSG_OFFSET :]

    def info(self) -> str:
        """Get object info.

        Returns a formatted string containing the response tag, status, and data bytes
        in hexadecimal format for debugging and logging purposes.

        :return: Formatted string with tag label, status label, and hex data.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        data = ", ".join(f"{b:02X}" for b in self.data)
        return f"Tag={tag}, Status={status}, Data={data}"


class MemWriteResponse(CmdResponse):
    """Memory write response format class.

    This class represents the response format for memory write operations in DK6 protocol,
    providing structured access to response data and status information.
    """

    def info(self) -> str:
        """Get object info.

        Returns formatted string containing tag and status information for the object.

        :return: Formatted string with tag and status details.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class MemEraseResponse(CmdResponse):
    """Memory erase response format class.

    This class represents the response format for memory erase operations in DK6 protocol,
    providing structured access to response data and status information.
    """

    def info(self) -> str:
        """Get object info.

        Returns formatted string containing tag and status information for the object.

        :return: Formatted string with tag and status labels.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class MemBlankCheckResponse(CmdResponse):
    """Memory blank check response format class.

    This class represents the response format for memory blank check operations
    in DK6 protocol, providing structured access to the response data and status
    information.
    """

    def info(self) -> str:
        """Get object info.

        Returns formatted string containing tag and status information for the object.

        :return: Formatted string with tag and status details.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class MemCloseResponse(CmdResponse):
    """DK6 memory close response format class.

    This class represents the response format for DK6 memory close operations,
    providing structured access to response data and status information.
    """

    def info(self) -> str:
        """Get object info.

        Returns formatted string containing tag and status information for the object.

        :return: Formatted string with tag and status details.
        """
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


def parse_cmd_response(data: bytes, frame_type: int) -> Union[
    CmdResponse,
    GenericResponse,
    GetChipIdResponse,
    MemOpenResponse,
    MemEraseResponse,
    MemBlankCheckResponse,
    MemReadResponse,
    MemWriteResponse,
    MemCloseResponse,
    MemGetInfoResponse,
    IspUnlockResponse,
]:
    """Parse command response based on frame type.

    This method analyzes the frame type and returns the appropriate response object
    for the given command. It supports various DK6 protocol responses including
    memory operations, chip identification, and ISP unlock commands.

    :param data: Raw response data received from the device.
    :param frame_type: Frame type identifier that determines response format.
    :return: Parsed response object specific to the command type, or generic
             CmdResponse if frame type is unknown.
    """
    known_response: dict[ResponseTag, Type[CmdResponse]] = {
        ResponseTag.RESET: GenericResponse,
        ResponseTag.EXECUTE: GenericResponse,
        ResponseTag.SET_BAUD: GenericResponse,
        ResponseTag.GET_CHIPID: GetChipIdResponse,
        ResponseTag.MEM_OPEN: MemOpenResponse,
        ResponseTag.MEM_ERASE: MemEraseResponse,
        ResponseTag.MEM_BLANK_CHECK: MemBlankCheckResponse,
        ResponseTag.MEM_READ: MemReadResponse,
        ResponseTag.MEM_WRITE: MemWriteResponse,
        ResponseTag.MEM_CLOSE: MemCloseResponse,
        ResponseTag.MEM_GET_INFO: MemGetInfoResponse,
        ResponseTag.UNLOCK_ISP: IspUnlockResponse,
    }
    for tag, cmd_response in known_response.items():
        if tag == frame_type:
            return cmd_response(frame_type, data)
    return CmdResponse(frame_type, data)
