#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Commands used in SmartCard."""

import logging
from struct import pack
from typing import Optional

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum

try:
    from smartcard.CardConnection import CardConnection
except ImportError as e:
    raise SPSDKError(
        "pyscard package is missing, please install it with pip install 'spsdk[tp]' in order to use TP"
    ) from e


from spsdk.tp.exceptions import SPSDKTpError

logger = logging.getLogger(__name__)


class StatusCodes(SpsdkEnum):
    """SmartCard APDU general status codes."""

    SEC_COND_NOT_SATISFIED = (0x6982, "SecCondNotSatisfied", "Security condition not satisfied")
    CMD_NOT_ALLOWED_EF = (0x6986, "CmdNotAllowedEF", "Command not allowed (no current EF)")

    FILE_INVALID = (0x6983, "FileInvalid", "File contains invalid data (key, counter)")
    WRONG_DATA = (0x6A80, "WrongData", "Data field of command contains wrong data.")
    FILE_NOT_FOUND = (0x6A82, "FileNotFound", "File not found")

    SUCCESS = (0x9000, "Success", "Success")
    KEY_NOT_FOUND = (0x9008, "Key/FileNotFound", "Key/file not found")
    CMD_NOT_SUPPORTED = (0x911C, "CmdNotSupported", "Command code not supported")
    APPLET_SEL_FAILED = (0x6999, "AppletSelFail", "Applet could not be found or selected")

    ARITHMETIC_ERROR = (0x5100, "ArithmeticError", "Arithmetic error")
    APDU_ERROR = (0x5200, "ApduError", "APDU error")
    CRYPTOGRAPHIC_ERROR = (0x5300, "CryptographicError", "Cryptographic error")
    SYSTEM_ERROR = (0x5400, "SystemError", "System error")
    GENERIC_ERROR = (0x6F00, "GenericError", "Generic error")

    MAX_COUNTER_REACHED = (0x5501, "CounterReached", "Max provisioning counter reached")
    COUNTER_NOT_INITIALIZED = (
        0x5502,
        "CounterNotInitialized",
        "Provisioning counter is not initialized (Smart card is probably not configured)",
    )
    VERIFICATION_ERROR = (0x6300, "VerificationError", "Public key can't be verified")


class SmartCardAPDU:
    """Implement SmartCard APDU's operation."""

    def __init__(
        self, cla: int, ins: int, p1: int, p2: int, data: Optional[bytes] = None, le: int = 0
    ) -> None:
        """Simple APDU transfer descriptor.

        :param cla: Class of instruction - indicates the structure and format for a category of
                    command and response APDUs
        :param ins: Instruction code: specifies the instruction of the command
        :param p1: Instruction parameter 1 - further provide qualifications to the instruction
        :param p2: Instruction parameter 2 - further provide qualifications to the instruction
        :param data: A sequence of bytes in the data field of the command
        :param le: Maximum of bytes expected in the data field of the response to the command
        """
        if cla not in [0x00, 0x80]:
            raise SPSDKTpError("CLA must be 0x00 or 0x80")
        if ins > 255:
            raise SPSDKTpError("INS must be less than 256")
        if p1 > 255:
            raise SPSDKTpError("P1 must be less than 256")
        if p2 > 255:
            raise SPSDKTpError("P2 must be less than 256")
        if le > 65535:
            raise SPSDKTpError("LE must be less than 65536")

        if data:
            if len(data) > 65535:
                raise SPSDKTpError("Data length must be less than 65536")

        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.lc = len(data) if data else 0
        self.data = data
        self.le = le
        self.is_extended = self.lc > 255 or self.le > 255
        self.status = 0
        self.response = bytes()

    def get_command(self) -> bytes:
        """Get binary command data."""
        fmt = "<BBBB"
        ret = pack(fmt, self.cla, self.ins, self.p1, self.p2)
        if self.data:
            ret += self.lc.to_bytes(
                length=3 if self.is_extended else 1, byteorder=Endianness.BIG.value
            )
            ret += self.data
        if self.le:
            ret += self.le.to_bytes(
                length=2 if self.is_extended else 1, byteorder=Endianness.BIG.value
            )
        return ret

    @classmethod
    def get_status_description(cls, code: int) -> str:
        """Return text description of status code."""
        desc = StatusCodes.get_description(code)
        if not desc:
            desc = StatusCodes.get_description(code & 0xFF00, "Unknown")
        return f"{hex(code)}: {desc}"

    @classmethod
    def format_error_message(cls, status_code: int, extra_message: Optional[str] = None) -> str:
        """Format error message.

        :param status_code: Status code of the operation.
        :param extra_message: Extra prefix in the error message, defaults to None
        :return: String representing the error.
        """
        message = extra_message or ""
        message += ": " if message else ""
        message += cls.get_status_description(status_code)
        return message

    def transmit(self, connection: CardConnection, extra_message: Optional[str] = None) -> bytes:
        """Transmit the command data using `connection`.

        :param connection: Connection to use for transmission
        :param extra_message: Extra message in case of an error, defaults to None
        :raises SPSDKTpError: If an error occurs (status != 0x9000)
        :return: Response data without status word
        """
        command_data = list(self.get_command())
        response, sw1, sw2 = connection.transmit(command_data)
        self.response = bytes(response)
        self.status = (sw1 << 8) + sw2
        if self.status != StatusCodes.SUCCESS:
            raise SPSDKTpError(self.format_error_message(self.status, extra_message))
        return self.response


#################################
# TRUST-PROVISIONING OPERATIONS #
#################################


class SetProvisioningItem(SmartCardAPDU):
    """Set provisioning data item."""

    def __init__(self, prov_item: int, data: bytes) -> None:
        """Set provisioning data item."""
        p1, p2 = int_to_p1p2(prov_item)
        super().__init__(cla=0x80, ins=0xDA, p1=p1, p2=p2, data=data)


class GetChallenge(SmartCardAPDU):
    """Get TP Challenge."""

    def __init__(self) -> None:
        """Get TP Challenge."""
        super().__init__(cla=0x00, ins=0x84, p1=0x00, p2=0x00)


class ProcessTPResponse(SmartCardAPDU):
    """Process the TP Response. Obtain the WRAPPED DATA."""

    def __init__(self, tp_response: bytes) -> None:
        """Process the TP Response. Obtain the WRAPPED DATA."""
        super().__init__(cla=0x00, ins=0x89, p1=0x00, p2=0x00, data=tp_response)


class GetProductionCounter(SmartCardAPDU):
    """Get Current value of the production counter."""

    def __init__(self) -> None:
        """Get Current value of the production counter."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x17)

    @staticmethod
    def format(response: bytes) -> int:
        """Format the `transmit` response into `int`."""
        return int.from_bytes(response, byteorder=Endianness.BIG.value)


class GetProductionRemainder(SmartCardAPDU):
    """Get Current value of the production counter."""

    def __init__(self) -> None:
        """Get Current value of the production counter."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x18)

    @staticmethod
    def format(response: bytes) -> int:
        """Format the `transmit` response into `int`."""
        return int.from_bytes(response, byteorder=Endianness.BIG.value)


class GetSealState(SmartCardAPDU):
    """Get current card seal state."""

    def __init__(self) -> None:
        """Get current card seal state."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x19)

    @staticmethod
    def format(response: bytes) -> bool:
        """Format the `transmit` response into `bool`."""
        return response == b"\x01"


class GetFamily(SmartCardAPDU):
    """Get family set in the smart card."""

    def __init__(self) -> None:
        """Get family set in the smart card."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x1A)

    @staticmethod
    def format(response: bytes) -> str:
        """Format the `transmit` response into `str`."""
        return response.decode("utf-8")


class Select(SmartCardAPDU):
    """APDU Select command."""

    def __init__(self, applet: str) -> None:
        """Select an applet with given name."""
        applet_id = applet.encode("utf-8")
        super().__init__(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, data=applet_id)


#######################
# GET DATA OPERATIONS #
#######################


class GetAppletName(SmartCardAPDU):
    """Get the applet name."""

    def __init__(self) -> None:
        """Get the applet name."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x00)

    @staticmethod
    def format(response: bytes) -> str:
        """Format the `transmit` response into `str`."""
        return bytes(response).decode("utf-8")


class GetSerialNumber(SmartCardAPDU):
    """Get Serial Number."""

    def __init__(self) -> None:
        """Get Serial Number."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x14)

    @staticmethod
    def format(response: bytes) -> int:
        """Format the `transmit` response into `int`."""
        return int.from_bytes(response, byteorder=Endianness.BIG.value)


class GetAppletVersion(SmartCardAPDU):
    """Get Applet version command."""

    def __init__(self) -> None:
        """Get Version command."""
        super().__init__(cla=0x00, ins=0xCA, p1=0x01, p2=0x16)

    @staticmethod
    def format(response: bytes) -> str:
        """Format the `transmit` response into `str`."""
        return ".".join(str(i) for i in response[:3])


class GetFreeMemory(SmartCardAPDU):
    """Get free memory."""

    def __init__(self, memory_type: int) -> None:
        """Get free memory of a given type.

        :param memory_type: 1 - NVM, 2 - COR, 3 - COD
        """
        super().__init__(cla=0x00, ins=0xCA, p1=0x02, p2=memory_type)

    @staticmethod
    def format(response: bytes) -> int:
        """Format the `transmit` response into `int`."""
        return int.from_bytes(response, byteorder=Endianness.BIG.value)


class Echo(SmartCardAPDU):
    """Send data and receive it back."""

    def __init__(self, data: Optional[bytes] = None) -> None:
        """Send `data` and receive it back."""
        super().__init__(cla=0x80, ins=0x00, p1=0x00, p2=0x00, data=data)


#####################
# BUFFER OPERATIONS #
#####################


class ResizeNVMBuffer(SmartCardAPDU):
    """Resize NVM buffer."""

    def __init__(self, new_length: int) -> None:
        """Resize NVM buffer to `new_length`."""
        length_data = new_length.to_bytes(length=2, byteorder=Endianness.BIG.value)
        super().__init__(cla=0x80, ins=0x84, p1=0x00, p2=0x00, data=length_data)


class DeleteNVMBuffer(SmartCardAPDU):
    """Delete NVM Buffer. Needs to be called before ResizeNVMBuffer."""

    def __init__(self) -> None:
        """Delete NVM Buffer."""
        super().__init__(cla=0x80, ins=0x84, p1=0x00, p2=0x00, data=bytes(2))


class ResizeTransientBuffer(SmartCardAPDU):
    """Resize NVM buffer."""

    def __init__(self, new_length: int) -> None:
        """Resize NVM buffer to `new_length`."""
        length_data = new_length.to_bytes(length=2, byteorder=Endianness.BIG.value)
        super().__init__(cla=0x80, ins=0x84, p1=0x00, p2=0x01, data=length_data)


class DeleteTransientBuffer(SmartCardAPDU):
    """Delete Transient Buffer. Needs to be called before ResizeTransientBuffer."""

    def __init__(self) -> None:
        """Delete Transient Buffer."""
        super().__init__(cla=0x80, ins=0x84, p1=0x00, p2=0x01, data=bytes(2))


##########################
# FILE SYSTEM OPERATIONS #
##########################


class CreateFileSystem(SmartCardAPDU):
    """Create File System on applet. Turns applet into PERSONALIZATION mode."""

    def __init__(self, objects_count: int = 18) -> None:
        """Create File System on applet."""
        super().__init__(cla=0x80, ins=0xE1, p1=00, p2=objects_count)


class DeleteFileSystem(SmartCardAPDU):
    """Delete the whole filesystem on applet. Turns applet into PRE-PERSONALIZATION mode."""

    def __init__(self) -> None:
        """Delete the whole filesystem on applet."""
        super().__init__(cla=0x80, ins=0xE4, p1=0x80, p2=0x00)


class DeleteFile(SmartCardAPDU):
    """Delete single file."""

    def __init__(self, file_index: int) -> None:
        """Delete single file with index `file_index`."""
        p1, p2 = int_to_p1p2(file_index)
        super().__init__(cla=0x00, ins=0xE4, p1=p1, p2=p2)


class FinalizeFileSystem(SmartCardAPDU):
    """Finalizes the file system personalization. Turns applet into OPERATIONAL mode."""

    def __init__(self) -> None:
        """Finalizes the file system personalization."""
        super().__init__(cla=0x80, ins=0x44, p1=0x00, p2=0x00)


def int_to_p1p2(param: int) -> tuple[int, int]:
    """Converts integer into the bytes (p1, p2)."""
    p1 = (param >> 8) & 0xFF
    p2 = param & 0xFF
    return p1, p2


def p1p2_to_int(p1: int, p2: int) -> int:
    """Converts two bytes (p1, p2) into integer."""
    param = p1 & 0xFF << 8 + p2 & 0xFF
    return param
