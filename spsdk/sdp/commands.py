#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SDP protocol commands and responses implementation.

This module provides command packet structures, response handling, and protocol
definitions for Serial Download Protocol (SDP) communication with NXP MCUs.
"""

from struct import pack, unpack_from

from spsdk.utils.interfaces.commands import CmdPacketBase, CmdResponseBase
from spsdk.utils.spsdk_enum import SpsdkEnum


########################################################################################################################
# SDP Command Tags
########################################################################################################################
class CommandTag(SpsdkEnum):
    """SDP Command Tags enumeration.

    This enumeration defines all available Serial Download Protocol (SDP) command tags
    used for communication with NXP MCU targets during secure provisioning operations.
    Each command represents a specific operation like reading/writing memory, jumping
    to addresses, or managing boot sequences.
    """

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
    """SDP Response Values enumeration.

    This enumeration defines standard response codes returned by SDP (Serial Download Protocol)
    operations, including success indicators for various commands and HAB (High Assurance Boot)
    status values.
    """

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
    """SDP command packet for device communication.

    This class encapsulates command data that can be serialized and sent to target devices
    through the Serial Download Protocol (SDP). It handles command formatting, validation,
    and binary export functionality.

    :cvar FORMAT: Binary format string for packet serialization.
    :cvar EMPTY_VALUE: Default empty value used in packet padding.
    """

    FORMAT = ">HIB2IB"
    EMPTY_VALUE = 0x00

    def __init__(self, tag: CommandTag, address: int, pformat: int, count: int, value: int = 0):
        """Initialize SDP command structure.

        Creates a new SDP (Serial Download Protocol) command with specified parameters
        for communication with the target device.

        :param tag: Command tag enumeration value representing the specific SDP command.
        :param address: Target memory address for the command operation.
        :param pformat: Data format specification (8=byte, 16=half-word, 32=word).
        :param count: Number of data units to process in the command.
        :param value: Optional data value for write operations, defaults to 0.
        """
        self.tag = tag.tag
        self.address = address
        self.format = pformat
        self.count = count
        self.value = value

    def __str__(self) -> str:
        """String representation of the command packet.

        Returns a formatted string containing the command's tag, address, format, count, and value
        in a human-readable format. The tag is displayed as a label if available, otherwise as hex.

        :return: Formatted string representation of the command packet.
        """
        return (
            f"Tag={CommandTag.get_label(self.tag) if self.tag in CommandTag.tags() else f'0x{self.tag:04X}'}, "
            f"Address=0x{self.address:04X}, Format={self.format}, Count={self.count}, Value=0x{self.value:08X}"
        )

    def export(self, padding: bool = True) -> bytes:
        """Return command packet as bytes.

        Exports the SDP command as a binary packet using the defined format structure.
        The packet includes tag, address, format, count, value fields and padding.

        :param padding: Whether to include padding in the exported packet, defaults to True.
        :return: Binary representation of the command packet.
        """
        return pack(self.FORMAT, self.tag, self.address, self.format, self.count, self.value, 0)


class CmdResponse(CmdResponseBase):
    """SDP command response handler.

    This class processes and interprets responses received from SDP (Serial Download Protocol)
    commands, providing convenient access to response values and status information including
    HAB (High Assurance Boot) status.
    """

    @property
    def value(self) -> int:
        """Get integer representation of the response.

        :return: Integer value extracted from the raw response data.
        """
        return unpack_from(">I", self.raw_data)[0]

    def __init__(self, hab: bool, raw_data: bytes):
        """Initialize the response object.

        :param hab: HAB status response flag indicating security state
        :param raw_data: Raw response data received from the target device
        """
        self.hab = hab
        self.raw_data = raw_data

    def __str__(self) -> str:
        """Return stringified information about the command response.

        Creates a human-readable string representation of the SDP command response,
        showing either a labeled response value or its hexadecimal representation.

        :return: Formatted string containing the response label or hex value.
        """
        label = (
            ResponseValue.get_label(self.value)
            if self.value in ResponseValue.tags()
            else f"0x{self.value:08X}"
        )
        return f"Response: {label}"
