#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USB SDP interface implementation."""
from dataclasses import dataclass
from typing import List, Optional

from typing_extensions import Self

from spsdk.sdp.protocol.bulk_protocol import SDPBulkProtocol
from spsdk.utils.interfaces.device.usb_device import UsbDevice


@dataclass
class ScanArgs:
    """Scan arguments dataclass."""

    device_id: str

    @classmethod
    def parse(cls, params: str) -> Self:
        """Parse given scanning parameters into ScanArgs class.

        :param params: Parameters as a string
        """
        return cls(device_id=params.replace(",", ":"))


USB_DEVICES = {
    # NAME    | VID   | PID
    "MX6DQP": (0x15A2, 0x0054),
    "MX6SDL": (0x15A2, 0x0061),
    "MX6SL": (0x15A2, 0x0063),
    "MX6SX": (0x15A2, 0x0071),
    "MX6UL": (0x15A2, 0x007D),
    "MX6ULL": (0x15A2, 0x0080),
    "MX6SLL": (0x15A2, 0x0128),
    "MX7SD": (0x15A2, 0x0076),
    "MX7ULP": (0x1FC9, 0x0126),
    "VYBRID": (0x15A2, 0x006A),
    "MXRT20": (0x1FC9, 0x0130),
    "MXRT50": (0x1FC9, 0x0130),
    "MXRT60": (0x1FC9, 0x0135),
    "MX8MQ": (0x1FC9, 0x012B),
    "MX8QXP-A0": (0x1FC9, 0x007D),
    "MX8QM-A0": (0x1FC9, 0x0129),
    "MX8QXP": (0x1FC9, 0x012F),
    "MX8QM": (0x1FC9, 0x0129),
    "MX815": (0x1FC9, 0x013E),
    "MX865": (0x1FC9, 0x0146),
    "MX91": (0x1FC9, 0x014E),
    "MX93": (0x1FC9, 0x014E),
    "MX95": (0x1FC9, 0x015D),  # USB port 1 PID: 0x015D, USB port 2 PID: 0x015C
}


class SdpUSBInterface(SDPBulkProtocol):
    """USB interface."""

    usb_devices = USB_DEVICES
    device: UsbDevice
    identifier = "usb"

    def __init__(self, device: UsbDevice) -> None:
        """Initialize the SdpUSBInterface object.

        :param device: The device instance
        """
        super().__init__(device=device)

    @classmethod
    def scan_from_args(
        cls,
        params: str,
        timeout: int,
        extra_params: Optional[str] = None,
    ) -> List[Self]:
        """Scan connected USB devices.

        :param params: Params as a configuration string
        :param extra_params: Extra params configuration string
        :param timeout: Timeout for the scan
        :return: list of matching RawHid devices
        """
        scan_args = ScanArgs.parse(params=params)
        interfaces = cls.scan(device_id=scan_args.device_id, timeout=timeout)
        return interfaces

    @classmethod
    def scan(
        cls,
        device_id: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> List[Self]:
        """Scan connected USB devices.

        :param device_id: Device identifier <vid>, <vid:pid>, device/instance path, device name are supported
        :param timeout: Read/write timeout
        :return: list of matching RawHid devices
        """
        devices = UsbDevice.scan(
            device_id=device_id, usb_devices_filter=cls.usb_devices, timeout=timeout
        )
        return [cls(device) for device in devices]
