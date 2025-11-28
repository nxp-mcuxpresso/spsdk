#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Serial Download Protocol Stream (SDPS) communication implementation.

This module provides functionality for secure communication with NXP MCU bootloaders
using the SDPS protocol. It includes command packet handling, ROM information management,
and secure provisioning operations.
"""

import logging
from dataclasses import dataclass
from struct import pack
from typing import Any

from spsdk.exceptions import SPSDKConnectionError, SPSDKError, SPSDKValueError
from spsdk.sdp.exceptions import SdpConnectionError
from spsdk.sdp.interfaces import SDPDeviceTypes
from spsdk.utils.database import DatabaseManager
from spsdk.utils.family import FamilyRevision
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.misc import swap32
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class CommandSignature(SpsdkEnum):
    """SDP command signature enumeration.

    This enumeration defines the signature values used to identify different types
    of SDP (Serial Download Protocol) command block wrappers in secure provisioning
    operations.
    """

    CBW_BLTC_SIGNATURE = (0x43544C42, "CbwBlts", "Command Block Wrapper BLTC")
    CBW_PITC_SIGNATURE = (0x43544950, "CbwPits", "Command Block Wrapper PITC")


class CommandFlag(SpsdkEnum):
    """SDP command flag enumeration for data transfer direction.

    This enumeration defines the direction flags used in SDP (Serial Download Protocol)
    commands to specify whether data flows from device to host or from host to device.
    """

    DEVICE_TO_HOST_DIR = (0x80, "DataOut", "Data Out")
    HOST_TO_DEVICE_DIR = (0x00, "DataIn", "Data In")


class CommandTag(SpsdkEnum):
    """SDP command tag enumeration.

    This enumeration defines the available command tags used in the Serial Download Protocol (SDP)
    for communication with NXP MCU devices during secure provisioning operations.
    """

    FW_DOWNLOAD = (2, "FwDownload", "Firmware download")


@dataclass
class RomInfo:
    """ROM information container for SDP communication parameters.

    This class holds configuration data about ROM capabilities and communication
    settings used during Serial Download Protocol (SDP) operations.
    """

    no_cmd: bool
    hid_ep1: bool
    hid_pack_size: int


class SDPS:
    """SDPS communication interface for NXP MCU devices.

    This class provides a high-level interface for communicating with NXP MCU devices
    using the Serial Downloader Protocol Stream (SDPS). It manages device connections,
    protocol parameters, and ROM-specific configurations across the supported MCU family
    portfolio.
    """

    def __init__(self, interface: SDPDeviceTypes, family: FamilyRevision) -> None:
        """Initialize SDPS object.

        :param interface: SDP device interface for communication.
        :param family: Target platform family and revision information.
        """
        self._interface = interface
        self.family = family

    @staticmethod
    def get_supported_families(include_predecessors: bool = False) -> list[FamilyRevision]:
        """Get supported families for SDPS protocol.

        Retrieves a list of device families that support the SDPS (Serial Download Protocol Stream)
        communication protocol. Optionally includes predecessor device families for backward compatibility.

        :param include_predecessors: Include predecessor family names in the result list.
        :return: List of family revisions that support SDPS protocol.
        """
        ret = [
            dev
            for dev, quick_info in DatabaseManager().quick_info.devices.devices.items()
            if quick_info.info.isp.is_protocol_supported("sdps")
        ]
        if include_predecessors:
            ret.extend(list(DatabaseManager().quick_info.devices.get_predecessors(ret).keys()))

        return [FamilyRevision(x) for x in ret]

    @property
    def rom_info(self) -> RomInfo:
        """Get ROM information for the current device family.

        Retrieves ROM protocol parameters from the device database including command
        support, HID endpoint configuration, and packet size settings.

        :return: ROM information object containing protocol parameters.
        """
        device = DatabaseManager().db.devices.get(self.family.name)
        return RomInfo(
            no_cmd=device.info.isp.rom.protocol_params.get("no_cmd", True),
            hid_ep1=device.info.isp.rom.protocol_params.get("hid_ep1", True),
            hid_pack_size=device.info.isp.rom.protocol_params.get("hid_pack_size", 1020),
        )

    @property
    def family(self) -> FamilyRevision:
        """Get device family and revision information.

        :return: Family and revision details of the connected device.
        """
        return self._family

    @family.setter
    def family(self, value: FamilyRevision) -> None:
        """Set device family for SDP communication.

        Validates that the specified family is supported before setting the internal
        family value.

        :param value: Device family revision to set.
        :raises SPSDKValueError: If the specified device family is not supported.
        """
        if value not in self.get_supported_families(True):
            raise SPSDKValueError(f"Device family is not supported {value}")
        self._family = value

    def __enter__(self) -> "SDPS":
        """Enter the runtime context of the SDPS object.

        This method is used as part of the context manager protocol to initialize
        the SDPS connection when entering a 'with' statement block.

        :return: The SDPS instance itself for use within the context block.
        """
        self.open()
        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        """Close the SDP connection and clean up resources.

        This method is called automatically when exiting a context manager (with statement)
        and ensures proper cleanup of the SDP connection.

        :param args: Variable length argument list (unused).
        :param kwargs: Arbitrary keyword arguments (unused).
        """
        self.close()

    def open(self) -> None:
        """Connect to i.MX device.

        Establishes connection to the i.MX device through the configured interface if not already connected.
        Logs the connection attempt with interface details.

        :raises SPSDKError: If the interface fails to open or connect to the device.
        """
        if not self.is_opened:
            logger.info(f"Connect: {str(self._interface)}")
            self._interface.open()

    def close(self) -> None:
        """Close the connection to the i.MX device.

        This method properly disconnects from the i.MX device and releases any
        associated resources through the underlying interface.

        :raises SPSDKError: If there's an error during the disconnection process.
        """
        self._interface.close()

    @property
    def is_opened(self) -> bool:
        """Check interface open status.

        :return: True if device is open, False if it's closed.
        """
        return self._interface.is_opened

    def write_file(self, data: bytes) -> None:
        """Write data to the target device.

        This method configures the interface and sends the boot image data to the target
        device. It handles command packet creation and data transmission according to the
        ROM information settings.

        :param data: The boot image data in binary format.
        :raises SdpConnectionError: Timeout or connection error during data transfer.
        :raises SPSDKError: Failure occurred in middle of transfer process.
        """
        try:
            self._interface.configure(
                {
                    "hid_ep1": self.rom_info.hid_ep1,
                    "pack_size": self.rom_info.hid_pack_size,
                }
            )
            if not self.rom_info.no_cmd:
                cmd_packet = CmdPacket(
                    signature=CommandSignature.CBW_BLTC_SIGNATURE.tag,
                    length=len(data),
                    flags=CommandFlag.HOST_TO_DEVICE_DIR,
                    command=CommandTag.FW_DOWNLOAD,
                )
                logger.info(f"TX-CMD: {cmd_packet})")
                self._interface.write_command(cmd_packet)
            try:
                self._interface.write_data(data)
            except SPSDKConnectionError as exc:
                raise SPSDKError(
                    "Probably invalid file content. " f"The low level error: {exc.description}"
                ) from exc
        except SPSDKError as exc:
            logger.info(f"RX-CMD: {exc}")
            raise SdpConnectionError(f"Writing file failed: {exc.description}") from exc

        logger.info(f"TX-CMD: WriteFile(length={len(data)})")


class CmdPacket(CmdPacketBase):
    """SDP Command Packet for device communication.

    This class represents a command packet structure used in Serial Download Protocol (SDP)
    communication with NXP devices. It encapsulates command data including signature, flags,
    and command type for reliable device interaction.

    :cvar FORMAT: Binary format string for packet serialization.
    """

    FORMAT = "<3IB2xbI11x"

    def __init__(
        self, signature: int, length: int, flags: CommandFlag, command: CommandTag, tag: int = 1
    ):
        """Initialize the SDP command structure.

        Creates a new SDP (Serial Download Protocol) command with the specified parameters
        for communication with the target device.

        :param signature: Command signature for validation
        :param length: Length of the command data
        :param flags: Command flags defining behavior and options
        :param command: Command tag specifying the operation type
        :param tag: Tag number representing the command, defaults to 1
        """
        self.signature = signature
        self.tag = tag
        self.length = length
        self.flags = flags
        self.cdb_command = command

    def __str__(self) -> str:
        """String representation of the command packet.

        :return: Formatted string containing signature, tag, length, flags, and CDB command values.
        """
        return (
            f"Signature={self.signature}, Tag=0x{self.tag},"
            f" Length={self.length}, Flags={self.flags}, CdbCommand=0x{self.cdb_command}"
        )

    def export(self, padding: bool = True) -> bytes:
        """Export command packet as bytes.

        Serializes the command packet structure into a binary format using the
        defined FORMAT string for transmission or storage.

        :param padding: Whether to include padding in the exported packet.
        :return: Binary representation of the command packet.
        """
        return pack(
            self.FORMAT,
            self.signature,
            self.tag,
            self.length,
            self.flags.tag,
            self.cdb_command.tag,
            swap32(self.length),
        )
