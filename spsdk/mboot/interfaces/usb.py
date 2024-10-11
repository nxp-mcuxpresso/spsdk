#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USB Mboot interface implementation."""

from typing import Optional

from typing_extensions import Self

from spsdk.mboot.protocol.bulk_protocol import MbootBulkProtocol
from spsdk.utils.database import DatabaseManager, UsbId
from spsdk.utils.interfaces.device.usb_device import UsbDevice


class MbootUSBInterface(MbootBulkProtocol):
    """USB interface."""

    identifier = "usb"
    device: UsbDevice

    def __init__(self, device: UsbDevice) -> None:
        """Initialize the MbootUSBInterface object.

        :param device: The device instance
        """
        assert isinstance(device, UsbDevice)
        super().__init__(device=device)

    @property
    def name(self) -> str:
        """Get the name of the device."""
        assert isinstance(self.device, UsbDevice)
        for name, usb_configs in self.get_devices().items():
            for usb_config in usb_configs:
                if usb_config.vid == self.device.vid and usb_config.pid == self.device.pid:
                    return name
        return "Unknown"

    @classmethod
    def get_devices(cls) -> dict[str, list[UsbId]]:
        """Get list of all supported devices from the database.

        :return: Dictionary containing device names with their usb configurations
        """
        devices = {}
        for device, quick_info in DatabaseManager().quick_info.devices.devices.items():
            usb_ids = quick_info.info.isp.get_usb_ids("mboot")
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

        :param device_id: Device identifier <vid>, <vid:pid>, device/instance path, device name are supported
        :param timeout: Read/write timeout
        :return: list of matching RawHid devices
        """
        devices = UsbDevice.scan(
            device_id=device_id, usb_devices_filter=cls.get_devices(), timeout=timeout
        )
        interfaces = [cls(device) for device in devices]
        return interfaces
