#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module implementing the SDPS communication protocol."""

import logging
from struct import pack
from typing import Mapping, Tuple

from spsdk.exceptions import SPSDKError
from spsdk.sdp.interfaces import SDPDeviceTypes
from spsdk.utils.easy_enum import Enum
from spsdk.utils.interfaces.commands import CmdPacketBase
from spsdk.utils.misc import swap32

from .exceptions import SdpConnectionError

logger = logging.getLogger(__name__)

ROM_INFO = {
    "MX8QXP": {"no_cmd": True, "hid_ep1": False, "hid_pack_size": 1024},
    "MX28": {"no_cmd": False, "hid_ep1": False, "hid_pack_size": 1024},
    "MX815": {"no_cmd": True, "hid_ep1": True, "hid_pack_size": 1020},
    "MX865": {"no_cmd": True, "hid_ep1": True, "hid_pack_size": 1020},
    "MX91": {"no_cmd": True, "hid_ep1": True, "hid_pack_size": 1020},
    "MX93": {"no_cmd": True, "hid_ep1": True, "hid_pack_size": 1020},
    "MX95": {"no_cmd": True, "hid_ep1": True, "hid_pack_size": 1020},
}


class CommandSignature(Enum):
    """Command signature enum."""

    CBW_BLTC_SIGNATURE = (0x43544C42, "CbwBlts", "Command Block Wrapper BLTC")
    CBW_PITC_SIGNATURE = (0x43544950, "CbwPits", "Command Block Wrapper PITC")


class CommandFlag(Enum):
    """Command flag enum."""

    DEVICE_TO_HOST_DIR = (0x80, "DataOut", "Data Out")
    HOST_TO_DEVICE_DIR = (0x00, "DataIn", "Data In")


class CommandTag(Enum):
    """Command tag enum."""

    FW_DOWNLOAD = (2, "FwDownload", "Firmware download")


class SDPS:
    """Secure Serial Downloader Protocol."""

    @property
    def name(self) -> str:
        """Get name."""
        return self.__name

    def __init__(self, interface: SDPDeviceTypes, device_name: str) -> None:
        """Initialize SDPS object.

        :param device: USB device
        :param device_name: target platform name used to determine ROM settings
        """
        self._interface = interface
        self.__name: str = device_name

    def __enter__(self) -> "SDPS":
        self.open()
        return self

    def __exit__(self, *args: Tuple, **kwargs: Mapping) -> None:
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
        """
        try:
            self._interface.configure(
                {
                    "hid_ep1": ROM_INFO[self.name]["hid_ep1"],
                    "pack_size": ROM_INFO[self.name]["hid_pack_size"],
                }
            )
            if not ROM_INFO[self.name]["no_cmd"]:
                cmd_packet = CmdPacket(
                    signature=CommandSignature.CBW_BLTC_SIGNATURE,
                    length=len(data),
                    flags=CommandFlag.HOST_TO_DEVICE_DIR,
                    command=CommandTag.FW_DOWNLOAD,
                )
                logger.info(f"TX-CMD: {cmd_packet})")
                self._interface.write_command(cmd_packet)
            self._interface.write_data(data)

        except SPSDKError as exc:
            logger.info(f"RX-CMD: {exc}")
            raise SdpConnectionError(f"Writing file failed: {exc}") from exc

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
            self.flags,
            self.cdb_command,
            swap32(self.length),
        )
