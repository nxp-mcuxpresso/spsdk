#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USB device interface implementation.

This module provides low-level USB device communication functionality
for SPSDK applications using the libusbsio library.
"""

import logging
from typing import Optional

import libusbsio
from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.utils.database import UsbId
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase
from spsdk.utils.misc import get_hash
from spsdk.utils.usbfilter import NXPUSBDeviceFilter, USBDeviceFilter

logger = logging.getLogger(__name__)


class UsbDevice(DeviceBase):
    """USB device interface for SPSDK communication.

    This class provides a USB HID device interface implementation that extends DeviceBase
    to enable communication with NXP MCU devices over USB. It manages USB device connection,
    data transfer operations, and device identification through vendor/product IDs and
    serial numbers.
    """

    def __init__(
        self,
        vid: Optional[int] = None,
        pid: Optional[int] = None,
        path: Optional[bytes] = None,
        serial_number: Optional[str] = None,
        vendor_name: Optional[str] = None,
        product_name: Optional[str] = None,
        interface_number: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the USB interface object.

        Creates a new USB device interface with the specified parameters for communication
        with NXP MCU devices through USB HID protocol.

        :param vid: USB Vendor ID of the target device.
        :param pid: USB Product ID of the target device.
        :param path: USB device path for direct device identification.
        :param serial_number: Serial number string of the target device.
        :param vendor_name: Vendor name string of the target device.
        :param product_name: Product name string of the target device.
        :param interface_number: USB interface number to use for communication.
        :param timeout: Communication timeout in milliseconds, defaults to 2000ms.
        """
        self._opened = False
        self.vid = vid or 0
        self.pid = pid or 0
        self.path = path or b""
        self.serial_number = serial_number or ""
        self.vendor_name = vendor_name or ""
        self.product_name = product_name or ""
        self.interface_number = interface_number or 0
        self._timeout = timeout or 2000
        libusbsio_logger = logging.getLogger("libusbsio")
        self._device: libusbsio.LIBUSBSIO.HID_DEVICE = libusbsio.usbsio(
            loglevel=libusbsio_logger.getEffectiveLevel()
        ).HIDAPI_DeviceCreate()

    @property
    def timeout(self) -> int:
        """Get timeout value for USB device communication.

        :return: Timeout value in milliseconds for USB operations.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set timeout value for USB device communication.

        :param value: Timeout value in milliseconds for USB operations.
        """
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False otherwise.
        """
        return self._opened

    def open(self) -> None:
        """Open the USB device interface.

        This method establishes a connection to the USB device using the stored device path.
        The device must not be already opened to avoid getting into a broken state.

        :raises SPSDKError: If device is already opened.
        :raises SPSDKConnectionError: If the device cannot be opened.
        """
        logger.debug(f"Opening the Interface: {str(self)}")
        if self.is_opened:
            # This would get HID_DEVICE into broken state
            raise SPSDKError("Can't open already opened device")
        try:
            self._device.Open(self.path)
            self._opened = True
        except Exception as error:
            raise SPSDKConnectionError(f"Unable to open device '{str(self)}'") from error

    def close(self) -> None:
        """Close the USB device interface.

        Properly closes the USB device connection and updates the interface state.
        If the device is not currently opened, the method does nothing.

        :raises SPSDKConnectionError: If the device cannot be closed due to underlying USB errors.
        """
        logger.debug(f"Closing the Interface: {str(self)}")
        if self.is_opened:
            try:
                self._device.Close()
                self._opened = False
            except Exception as error:
                raise SPSDKConnectionError(f"Unable to close device '{str(self)}'") from error

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data on the IN endpoint associated to the HID interface.

        :param length: Number of bytes to read from the device.
        :param timeout: Timeout in milliseconds for the read operation, uses default if None.
        :return: Raw data bytes read from the device.
        :raises SPSDKConnectionError: Device is not opened for reading.
        :raises SPSDKConnectionError: Device is not available or reading fails.
        :raises SPSDKTimeoutError: Read operation timed out.
        """
        timeout = timeout or self.timeout
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for reading")
        try:
            (data, result) = self._device.Read(length, timeout_ms=timeout)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if not data:
            logger.debug(f"Cannot read from HID device, error={result}")
            raise SPSDKTimeoutError()
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        Writes the provided data bytes to the connected USB device using the specified timeout.

        :param data: Data bytes to send to the device.
        :param timeout: Timeout in milliseconds for the write operation, uses default if None.
        :raises SPSDKConnectionError: Device is not opened or data transmission failed.
        """
        timeout = timeout or self.timeout
        if not self.is_opened:
            raise SPSDKConnectionError("Device is not opened for writing")
        try:
            bytes_written = self._device.Write(data, timeout_ms=timeout)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if bytes_written < 0 or bytes_written < len(data):
            raise SPSDKConnectionError(
                f"Invalid size of written bytes has been detected: {bytes_written} != {len(data)}"
            )

    def __str__(self) -> str:
        """Return string representation of the USB device interface.

        Provides a formatted string containing the product name, vendor ID, product ID,
        device path, and serial number for identification purposes.

        :return: Formatted string with USB device information including product name,
            VID/PID in hexadecimal format, device path, and serial number.
        """
        return (
            f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"
            f"path={self.path!r} sn='{self.serial_number}'"
        )

    @property
    def path_str(self) -> str:
        """Get BLHost-friendly string representation of USB path.

        Converts the USB device path to a format that is compatible with BLHost tool
        for device identification and communication.

        :return: BLHost-compatible USB path string.
        """
        return NXPUSBDeviceFilter.convert_usb_path(self.path)

    @property
    def path_hash(self) -> str:
        """Get BLHost-friendly hash of the USB path.

        :return: Hash string representation of the USB device path.
        """
        return get_hash(self.path)

    def __hash__(self) -> int:
        """Get hash value for the USB device.

        The hash is computed based on the device path to enable proper usage
        in hash-based collections like sets and dictionaries.

        :return: Hash value of the device path.
        """
        return hash(self.path)

    @classmethod
    def scan(
        cls,
        device_id: Optional[str] = None,
        usb_devices_filter: Optional[dict[str, list[UsbId]]] = None,
        timeout: Optional[int] = None,
    ) -> list[Self]:
        """Scan connected USB devices.

        Scans for USB devices that match the specified criteria. The method can filter
        devices by device identifier, NXP device types, and apply custom timeout settings.

        :param device_id: Device identifier supporting <vid>, <vid:pid>, device/instance path,
            or device name formats.
        :param usb_devices_filter: Dictionary mapping device names to USB ID lists in format
            {"device_name": [UsbId objects]}. When provided, only matching devices are scanned.
        :param timeout: Read/write timeout in seconds for device communication.
        :return: List of matching USB device instances.
        """
        usb_filter = NXPUSBDeviceFilter(usb_id=device_id, nxp_device_names=usb_devices_filter)
        devices = cls.enumerate(usb_filter, timeout=timeout)
        return devices

    @classmethod
    def enumerate(
        cls, usb_device_filter: USBDeviceFilter, timeout: Optional[int] = None
    ) -> list[Self]:
        """Enumerate all connected USB devices matching the specified filter criteria.

        This method scans for HID devices using libusbsio and filters them based on the
        provided USB device filter. Each matching device is instantiated as a new device
        object with the discovered properties.

        :param usb_device_filter: Filter object to match against discovered USB devices
        :param timeout: Optional timeout value in seconds to set for device operations
        :return: List of USB device instances that match the filter criteria
        """
        devices = []
        libusbsio_logger = logging.getLogger("libusbsio")
        sio = libusbsio.usbsio(loglevel=libusbsio_logger.getEffectiveLevel())
        all_hid_devices = sio.HIDAPI_Enumerate()

        # iterate on all devices found
        for dev in all_hid_devices:
            if usb_device_filter.compare(vars(dev)) is True:
                new_device = cls(
                    vid=dev["vendor_id"],
                    pid=dev["product_id"],
                    path=dev["path"],
                    vendor_name=dev["manufacturer_string"],
                    product_name=dev["product_string"],
                    interface_number=dev["interface_number"],
                    timeout=timeout,
                )
                devices.append(new_device)
        return devices
