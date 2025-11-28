#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USB interface implementation for MBoot communication protocol.

This module provides USB-based communication interface for MBoot protocol,
enabling secure provisioning operations over USB connections with NXP MCUs.
"""

from typing import Optional

from typing_extensions import Self

from spsdk.mboot.protocol.bulk_protocol import MbootBulkProtocol
from spsdk.utils.database import DatabaseManager, UsbId
from spsdk.utils.interfaces.device.usb_device import UsbDevice


class MbootUSBInterface(MbootBulkProtocol):
    """MbootUSB interface for NXP MCU communication.

    This class provides USB communication interface for MBoot protocol operations,
    enabling device discovery, connection management, and data transfer over USB.
    It extends the bulk protocol implementation with USB-specific functionality
    for scanning and identifying connected NXP devices.

    :cvar identifier: Interface type identifier for USB communication.
    """

    identifier = "usb"
    device: UsbDevice

    def __init__(self, device: UsbDevice) -> None:
        """Initialize the MbootUSBInterface object.

        :param device: The USB device instance to be used for communication.
        :raises AssertionError: If device is not an instance of UsbDevice.
        """
        assert isinstance(device, UsbDevice)
        super().__init__(device=device)

    @property
    def name(self) -> str:
        """Get the name of the USB device.

        Searches through available USB device configurations to find a matching
        device based on VID and PID, then returns the corresponding device name.

        :return: Name of the device if found in configurations, otherwise "Unknown".
        """
        assert isinstance(self.device, UsbDevice)
        for name, usb_configs in self.get_devices().items():
            for usb_config in usb_configs:
                if usb_config.vid == self.device.vid and usb_config.pid == self.device.pid:
                    return name
        return "Unknown"

    @classmethod
    def get_devices(cls) -> dict[str, list[UsbId]]:
        """Get list of all supported devices from the database.

        The method retrieves device information from the database manager and filters devices
        that have USB configurations available for mboot interface.

        :return: Dictionary with device names as keys and lists of UsbId objects as values.
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

        Searches for and identifies USB devices that match the specified criteria,
        creating interface instances for each discovered device.

        :param device_id: Device identifier supporting multiple formats: <vid>, <vid:pid>,
            device/instance path, or device name
        :param timeout: Read/write timeout in seconds for device communication
        :return: List of matching RawHid device interface instances
        """
        devices = UsbDevice.scan(
            device_id=device_id, usb_devices_filter=cls.get_devices(), timeout=timeout
        )
        interfaces = [cls(device) for device in devices]
        return interfaces
