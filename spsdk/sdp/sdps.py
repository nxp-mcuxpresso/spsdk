#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDPS communication protocol."""

import logging
from dataclasses import dataclass
from struct import pack
from typing import Any

from spsdk.exceptions import SPSDKConnectionError, SPSDKError, SPSDKValueError
from spsdk.sdp.exceptions import SdpConnectionError
from spsdk.sdp.interfaces import SDPDeviceTypes
from spsdk.utils.database import DatabaseManager
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.misc import swap32
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class CommandSignature(SpsdkEnum):
    """Command signature enum."""

    CBW_BLTC_SIGNATURE = (0x43544C42, "CbwBlts", "Command Block Wrapper BLTC")
    CBW_PITC_SIGNATURE = (0x43544950, "CbwPits", "Command Block Wrapper PITC")


class CommandFlag(SpsdkEnum):
    """Command flag enum."""

    DEVICE_TO_HOST_DIR = (0x80, "DataOut", "Data Out")
    HOST_TO_DEVICE_DIR = (0x00, "DataIn", "Data In")


class CommandTag(SpsdkEnum):
    """Command tag enum."""

    FW_DOWNLOAD = (2, "FwDownload", "Firmware download")


@dataclass
class RomInfo:
    """Rom information."""

    no_cmd: bool
    hid_ep1: bool
    hid_pack_size: int


class SDPS:
    """Secure Serial Downloader Protocol."""

    def __init__(self, interface: SDPDeviceTypes, family: str) -> None:
        """Initialize SDPS object.

        :param device: USB device
        :param device_name: target platform name used to determine ROM settings
        """
        self._interface = interface
        self.family: str = family

    @staticmethod
    def get_supported_families() -> list[str]:
        """Get supported devices.

        :return: List of supported devices
        """
        return [
            dev
            for dev, quick_info in DatabaseManager().quick_info.devices.devices.items()
            if quick_info.info.isp.is_protocol_supported("sdps")
        ]

    @property
    def rom_info(self) -> RomInfo:
        """Rom information property."""
        device = DatabaseManager().db.devices.get(self.family)
        return RomInfo(
            no_cmd=device.info.isp.rom.protocol_params.get("no_cmd", True),
            hid_ep1=device.info.isp.rom.protocol_params.get("hid_ep1", True),
            hid_pack_size=device.info.isp.rom.protocol_params.get("hid_pack_size", 1020),
        )

    @property
    def family(self) -> str:
        """Device name."""
        return self._family

    @family.setter
    def family(self, value: str) -> None:
        """Device name setter."""
        devices = self.get_supported_families()
        devices += list(DatabaseManager().quick_info.devices.get_predecessors(devices).keys())
        if value not in devices:
            raise SPSDKValueError(f"Device family is not supported {value}")
        self._family = value

    def __enter__(self) -> "SDPS":
        self.open()
        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> None:
        self.close()

    def open(self) -> None:
        """Connect to i.MX device."""
        if not self.is_opened:
            logger.info(f"Connect: {str(self._interface)}")
            self._interface.open()

    def close(self) -> None:
        """Disconnect i.MX device."""
        self._interface.close()

    @property
    def is_opened(self) -> bool:
        """Indicates whether the underlying interface is open.

        :return: True if device is open, False if it's closed
        """
        return self._interface.is_opened

    def write_file(self, data: bytes) -> None:
        """Write data to the target.

        :param data: The boot image data in binary format
        :raises SdpConnectionError: Timeout or Connection error
        :raises SPSDKError: Fail in middle of transfer
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
    """Class representing a command packet to be sent to device."""

    FORMAT = "<3IB2xbI11x"

    def __init__(
        self, signature: int, length: int, flags: CommandFlag, command: CommandTag, tag: int = 1
    ):
        """Initialize the struct.

        :param tag: Tag number representing the command
        :param address: Address used by the command
        :param pformat: Format of the data: 8 = byte, 16 = half-word, 32 = word
        :param count: Count used by individual command
        :param value: Value to use in a particular command, defaults to 0
        """
        self.signature = signature
        self.tag = tag
        self.length = length
        self.flags = flags
        self.cdb_command = command

    def __str__(self) -> str:
        """String representation of the command packet."""
        return (
            f"Signature={self.signature}, Tag=0x{self.tag},"
            f" Length={self.length}, Flags={self.flags}, CdbCommand=0x{self.cdb_command}"
        )

    def to_bytes(self, padding: bool = True) -> bytes:
        """Return command packet as bytes."""
        return pack(
            self.FORMAT,
            self.signature,
            self.tag,
            self.length,
            self.flags.tag,
            self.cdb_command.tag,
            swap32(self.length),
        )
