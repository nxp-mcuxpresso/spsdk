#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USB SDP interface implementation."""
from typing import Dict, List, Optional

from typing_extensions import Self

from spsdk.sdp.protocol.bulk_protocol import SDPBulkProtocol
from spsdk.utils.database import DatabaseManager, UsbId
from spsdk.utils.interfaces.device.usb_device import UsbDevice


class SdpUSBInterface(SDPBulkProtocol):
    """USB interface."""

    device: UsbDevice
    identifier = "usb"

    def __init__(self, device: UsbDevice) -> None:
        """Initialize the SdpUSBInterface object.

        :param device: The device instance
        """
        super().__init__(device=device)

    @classmethod
    def get_devices(cls) -> Dict[str, List[UsbId]]:
        """Get list of all supported devices from the database.

        :return: Dictionary containing device names with their usb configurations
        """
        devices = {}
        for device in DatabaseManager().db.devices:
            usb_ids = device.info.isp.get_usb_ids("sdp")
            usb_ids.extend(device.info.isp.get_usb_ids("sdps"))
            if usb_ids:
                devices[device.name] = usb_ids
        return devices

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
        all_devices = UsbDevice.scan(
            device_id=device_id, usb_devices_filter=cls.get_devices(), timeout=timeout
        )
        return [cls(device) for device in all_devices]
