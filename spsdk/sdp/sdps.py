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

from spsdk.sdp.interfaces import SDPDeviceTypes
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

BLTC_DOWNLOAD_FW = 2
CBW_BLTC_SIGNATURE = 0x43544C42

CBW_DEVICE_TO_HOST_DIR = 0x80  # "Data Out"
CBW_HOST_TO_DEVICE_DIR = 0x00  # "Data In"


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
        _format = "<3IB2xbI11x"

        try:
            self._interface.configure(
                {
                    "hid_ep1": ROM_INFO[self.name]["hid_ep1"],
                    "pack_size": ROM_INFO[self.name]["hid_pack_size"],
                }
            )
            if not ROM_INFO[self.name]["no_cmd"]:
                cmd_packet = pack(
                    _format,
                    CBW_BLTC_SIGNATURE,
                    1,
                    len(data),
                    CBW_HOST_TO_DEVICE_DIR,
                    BLTC_DOWNLOAD_FW,
                    swap32(len(data)),
                )
                logger.info(
                    f"TX-CMD: WriteCmd(command={BLTC_DOWNLOAD_FW},"
                    f" flags=0x{CBW_HOST_TO_DEVICE_DIR:08X},"
                    f" length={len(cmd_packet)})"
                )
                self._interface.device.write(cmd_packet)

            self._interface.device.write(data)

        except Exception as exc:
            logger.info("RX-CMD: Timeout Error")
            raise SdpConnectionError("Timeout Error") from exc

        logger.info(f"TX-CMD: WriteFile(length={len(data)})")
