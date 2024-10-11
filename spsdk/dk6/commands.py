#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""DK6 Device Commands."""
from struct import unpack_from
from typing import Type, Union

from spsdk.utils.spsdk_enum import SpsdkEnum


class StatusCode(SpsdkEnum):
    """DK6 Command Status Codes."""

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
    """DK6 Responses to Commands."""

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
    """DK6 Commands."""

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
    """DK6 Memory IDs."""

    FLASH = (0x00, "FLASH")
    PSECT = (0x01, "PSECT")
    pFLASH = (0x02, "pFLASH")
    Config = (0x03, "Config")
    EFUSE = (0x04, "EFUSE")
    ROM = (0x05, "ROM")
    RAM0 = (0x06, "RAM0")
    RAM1 = (0x07, "RAM1")


class MemoryType(SpsdkEnum):
    """DK6 Memory Types."""

    ROM = (0x00, "ROM", "Read only memory")
    FLASH = (0x01, "FLASH", "FLASH memory")
    RAM = (0x02, "RAM", "RAM")
    EFUSE = (0x05, "EFUSE (OTP)", "EFUSE (OTP)")


class MemoryAccessValues(SpsdkEnum):
    """DK6 Memory Access Values."""

    READ = (0x00, "Read Enabled")
    WRITE = (0x01, "Write Enabled")
    ERASE = (0x02, "Erase Enabled")
    ERASE_ALL = (0x03, "Erase All Enabled")
    BLANK_CHECK_ENABLED = (0x04, "Blank Check Enabled")
    ALL = (0x0F, "All is available")


class CmdPacket:
    """DK6 command packet format class."""

    def __init__(self, data: bytes) -> None:
        """Initialize the Command Packet object.

        :param data: Command data, defaults to None
        """
        self.data = data

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, CmdPacket) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        return not self.__eq__(obj)

    def __str__(self) -> str:
        return "<" + self.info() + ">"

    def info(self) -> str:
        """Get object info."""
        return "CMDPacket[" + ", ".join(f"{b:02X}" for b in self.data) + "]"

    def to_bytes(self) -> Union[bytes, None]:
        """Serialize CmdPacket into bytes.

        :return: Serialized object into bytes
        """
        return self.data


class CmdResponse:
    """DK6 response base format class."""

    MSG_OFFSET = 1

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        assert isinstance(raw_data, (bytes, bytearray))
        self.type = cmd_type
        self.status = raw_data[0]
        self.raw_data = raw_data

    def __eq__(self, obj: object) -> bool:
        return isinstance(obj, CmdResponse) and vars(obj) == vars(self)

    def __ne__(self, obj: object) -> bool:
        return not self.__eq__(obj)

    def __str__(self) -> str:
        return "<" + self.info() + ">"

    def info(self) -> str:
        """Get object info."""
        return (
            f"Status=0x{self.status:02X}"
            + f"Type=0x{self.type:02X}"
            + " ["
            + ", ".join(f"{b:02X}" for b in self.raw_data)
            + "]"
        )

    def _get_status_label(self) -> str:
        return (
            StatusCode.get_label(self.status)
            if StatusCode.contains(self.status)
            else f"Unknown[0x{self.status:08X}]"
        )


class GenericResponse(CmdResponse):
    """DK6 generic response format class."""

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class IspUnlockResponse(CmdResponse):
    """ISP Unlock response format class."""

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(cmd_type, raw_data)
        self.authenticated = self.status == StatusCode.OK

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}, Authenticated={self.authenticated}"


class GetChipIdResponse(CmdResponse):
    """Chip get info response format class."""

    FORMAT = "<II"

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Once response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(cmd_type, raw_data)
        if self.status == StatusCode.OK:
            (self.chip_id, self.chip_version) = unpack_from(self.FORMAT, raw_data, self.MSG_OFFSET)

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        if self.status == StatusCode.OK:
            return f"Tag={tag}, Status={status}, ChipID={hex(self.chip_id)}, ChipVersion={hex(self.chip_version)}"
        return f"Tag={tag}, Status={status}"


class MemGetInfoResponse(CmdResponse):
    """Memory get info response format class."""

    FORMAT = "<BIIIBB"
    MEM_NAME_OFFSET = 15

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Flash-Read-Once response object.

        :param header: Header for the response
        :param raw_data: Response data
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
        """Get object info."""
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
    """Memory open response format class."""

    FORMAT = "<B"

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(cmd_type, raw_data)
        if self.status == StatusCode.OK:
            self.handle = unpack_from(self.FORMAT, raw_data, self.MSG_OFFSET)

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        if self.status == StatusCode.OK:
            return f"Tag={tag}, Status={status}, Handle={self.handle}"
        return f"Tag={tag}, Status={status}"


class MemReadResponse(CmdResponse):
    """Memory open response format class."""

    def __init__(self, cmd_type: int, raw_data: bytes) -> None:
        """Initialize the Command Response object.

        :param header: Header for the response
        :param raw_data: Response data
        """
        super().__init__(cmd_type, raw_data)
        self.data = b""
        if self.status == StatusCode.OK:
            self.data = self.raw_data[self.MSG_OFFSET :]

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        data = ", ".join(f"{b:02X}" for b in self.data)
        return f"Tag={tag}, Status={status}, Data={data}"


class MemWriteResponse(CmdResponse):
    """Memory open response format class."""

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class MemEraseResponse(CmdResponse):
    """Memory open response format class."""

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class MemBlankCheckResponse(CmdResponse):
    """Memory open response format class."""

    def info(self) -> str:
        """Get object info."""
        tag = ResponseTag.get_label(self.type)
        status = self._get_status_label()
        return f"Tag={tag}, Status={status}"


class MemCloseResponse(CmdResponse):
    """DK6 memory close response format class."""

    def info(self) -> str:
        """Get object info."""
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
    """Parse command response.

    :param data: Input data in bytes
    :param frame_type: Frame Type
    :return: De-serialized object from data
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
