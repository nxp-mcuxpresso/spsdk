#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USB interface implementation for Serial Download Protocol (SDP).

This module provides USB communication interface for SDP operations,
enabling secure provisioning and device management over USB connections
for NXP MCU devices.
"""

from typing import Optional

from typing_extensions import Self

from spsdk.sdp.protocol.bulk_protocol import SDPBulkProtocol
from spsdk.utils.database import DatabaseManager, UsbId
from spsdk.utils.interfaces.device.usb_device import UsbDevice


class SdpUSBInterface(SDPBulkProtocol):
    """SDP USB interface for NXP MCU communication.

    This class provides USB-based communication interface for Serial Download Protocol (SDP)
    operations. It handles USB device discovery, connection management, and data transfer
    for secure provisioning and firmware download operations across NXP MCU portfolio.

    :cvar identifier: Interface type identifier for USB communication.
    """

    device: UsbDevice
    identifier = "usb"

    def __init__(self, device: UsbDevice) -> None:
        """Initialize the SdpUSBInterface object.

        :param device: The USB device instance to be used for SDP communication.
        """
        super().__init__(device=device)

    @classmethod
    def get_devices(cls) -> dict[str, list[UsbId]]:
        """Get list of all supported devices from the database.

        The method retrieves device information from the database manager and filters devices that
        have USB configurations for SDP (Serial Download Protocol) or SDPS (Serial Download
        Protocol Stream) interfaces.

        :return: Dictionary with device names as keys and lists of UsbId objects as values.
        """
        devices = {}
        for device, quick_info in DatabaseManager().quick_info.devices.devices.items():
            usb_ids = quick_info.info.isp.get_usb_ids("sdp")
            usb_ids.extend(quick_info.info.isp.get_usb_ids("sdps"))
            if usb_ids:
                devices[device] = usb_ids
        return devices

    @classmethod
    def scan(
        cls,
        device_id: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected USB devices.

        :param device_id: Device identifier <vid>, <vid:pid>, device/instance path, device name are supported.
        :param timeout: Read/write timeout in seconds.
        :return: List of matching RawHid devices.
        """
        all_devices = UsbDevice.scan(
            device_id=device_id, usb_devices_filter=cls.get_devices(), timeout=timeout
        )
        return [cls(device) for device in all_devices]
