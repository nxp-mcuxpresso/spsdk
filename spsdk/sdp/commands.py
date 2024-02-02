#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Commands and responses used by SDP module."""

from struct import pack, unpack_from

from spsdk.utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from spsdk.utils.spsdk_enum import SpsdkEnum


########################################################################################################################
# SDP Command Tags
########################################################################################################################
class CommandTag(SpsdkEnum):
    """SDP Commands."""

    READ_REGISTER = (0x0101, "ReadRegister", "Read data from memory or registers")
    WRITE_REGISTER = (
        0x0202,
        "WriteRegister",
        "Write one word (max 4 bytes) into memory or register",
    )
    WRITE_FILE = (0x0404, "WriteFile", "Write file (boot image) into memory")
    ERROR_STATUS = (0x0505, "ErrorStatus", "Read error code")
    WRITE_CSF = (0x0606, "WriteCsf", "Write CSF data into target")
    WRITE_DCD = (0x0A0A, "WriteDcd", "Write DCD data into target")
    SKIP_DCD_HEADER = (0x0C0C, "SkipDcdHeader", "Skip DCD content from loaded image")
    JUMP_ADDRESS = (0x0B0B, "JumpAddress", "Jump to specified address and run")
    SET_BAUDRATE = (0x0D0D, "SetBaudrate")
    PING = (0x5AA6, "Ping")


########################################################################################################################
# SDP Response Values
########################################################################################################################
class ResponseValue(SpsdkEnum):
    """SDP Response Values."""

    WRITE_DATA_OK = (0x128A8A12, "WRITE_DATA_OK", "Write Data Success")
    WRITE_FILE_OK = (0x88888888, "WRITE_FILE_OK", "Write File Success")
    SKIP_DCD_HEADER_OK = (0x900DD009, "SKIP_DCD_HEADER_OK", "Skip DCD Header Success")

    LOCKED = (0x12343412, "LOCKED", "HAB Is Enabled (Locked)")
    UNLOCKED = (0x56787856, "UNLOCKED", "Hab Is Disabled (Unlocked)")

    HAB_SUCCESS = (0xF0F0F0F0, "HAB_SUCCESS", "HAB Success")
    BAUDRATE_SET = (0x09D00D90, "BAUDRATE_SET", "Baudrate Setup Success")


########################################################################################################################
# SDP Command and Response packet classes
########################################################################################################################


class CmdPacket(CmdPacketBase):
    """Class representing a command packet to be sent to device."""

    FORMAT = ">HIB2IB"
    EMPTY_VALUE = 0x00

    def __init__(self, tag: CommandTag, address: int, pformat: int, count: int, value: int = 0):
        """Initialize the struct.

        :param tag: Tag number representing the command
        :param address: Address used by the command
        :param pformat: Format of the data: 8 = byte, 16 = half-word, 32 = word
        :param count: Count used by individual command
        :param value: Value to use in a particular command, defaults to 0
        """
        self.tag = tag.tag
        self.address = address
        self.format = pformat
        self.count = count
        self.value = value

    def __str__(self) -> str:
        """String representation of the command packet."""
        return (
            f"Tag={CommandTag.get_label(self.tag) if self.tag in CommandTag.tags() else f'0x{self.tag:04X}'}, "
            f"Address=0x{self.address:04X}, Format={self.format}, Count={self.count}, Value=0x{self.value:08X}"
        )

    def to_bytes(self, padding: bool = True) -> bytes:
        """Return command packet as bytes."""
        return pack(self.FORMAT, self.tag, self.address, self.format, self.count, self.value, 0)


class CmdResponse(CmdResponseBase):
    """Response on the previously issued command."""

    @property
    def value(self) -> int:
        """Return a integer representation of the response."""
        return unpack_from(">I", self.raw_data)[0]

    def __init__(self, hab: bool, raw_data: bytes):
        """Initialize the response object.

        :param hab: HAB status response
        :param raw_data: Data sent by the device
        """
        self.hab = hab
        self.raw_data = raw_data

    def __str__(self) -> str:
        """Return stringified information about the command response."""
        label = (
            ResponseValue.get_label(self.value)
            if self.value in ResponseValue.tags()
            else f"0x{self.value:08X}"
        )
        return f"Response: {label}"
