#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK device description classes for various communication interfaces.

This module provides abstract and concrete device description classes for different
communication protocols used with NXP devices, including UART, USB, UUU, SDIO,
and SIO interfaces.
"""


from abc import ABC, abstractmethod
from typing import Optional, Union

from libusbsio.libusbsio import LIBUSBSIO

from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.sdp.interfaces.usb import SdpUSBInterface
from spsdk.utils.database import UsbId
from spsdk.utils.misc import get_hash

# for backward-compatibility
from spsdk.utils.usbfilter import NXPUSBDeviceFilter

convert_usb_path = NXPUSBDeviceFilter.convert_usb_path


class DeviceDescription(ABC):
    """Abstract base class for device description containers.

    This class provides a generic interface for representing information about
    devices of any type without providing device control capabilities. It serves
    as a foundation for creating concrete device description implementations that
    can store and present device metadata, identifiers, and properties.
    Subclasses must implement the abstract methods to provide device-specific
    string representations and information formatting.
    """

    def __repr__(self) -> str:
        """Return string representation of the object.

        This method provides a developer-friendly string representation that includes
        the class name and all instance variables.

        :return: String representation containing class name and instance variables.
        """
        return f"{self.__class__.__name__}({vars(self)})"

    @abstractmethod  # pragma: no cover
    def __str__(self) -> str:
        """Get string representation of the device.

        Returns a formatted string containing device information such as name and ID.

        :return: String describing the device in format "Name: <name>; ID: <id>".
        """


class UartDeviceDescription(DeviceDescription):
    """UART device description container for SPSDK operations.

    This container holds UART device information and provides a consistent interface
    across different UART API implementations, ensuring stable device representation
    regardless of the underlying UART library used.
    """

    def __init__(self, name: Optional[str] = None, dev_type: Optional[str] = None) -> None:
        """Initialize device description with port name and device type.

        The 'dev_type' can be in general any string identifying the device type.

        :param name: COM port name, defaults to "Unknown port" if not provided.
        :param dev_type: Device type identifier such as 'mboot device' or 'SDP device',
            defaults to "Unknown device type" if not provided.
        """
        self.name = name or "Unknown port"
        self.dev_type = dev_type or "Unknown device type"

    def __str__(self) -> str:
        """Return formatted device description string.

        :return: Text information about device including port name and device type.
        """
        return f"Port: {self.name}\nType: {self.dev_type}"


class USBDeviceDescription(DeviceDescription):
    """USB device description container for SPSDK operations.

    This container provides a standardized representation of USB device information
    that remains consistent across different USB API implementations. It abstracts
    USB device details into a portable format suitable for device identification
    and management within SPSDK workflows.
    """

    def __init__(
        self,
        vid: int,
        pid: int,
        path: str,
        product_string: str,
        manufacturer_string: str,
        name: str,
        serial: str,
        original_path: Optional[Union[str, bytes]] = None,
    ) -> None:
        """Initialize USB device description.

        Creates a new device description instance with USB device information
        including vendor/product IDs, device strings, and path information.

        :param vid: Vendor ID of the USB device.
        :param pid: Product ID of the USB device.
        :param path: Device path string for communication.
        :param product_string: Product name string from USB descriptor.
        :param manufacturer_string: Manufacturer name string from USB descriptor.
        :param name: Name(s) of NXP devices as defined under spsdk.mboot.interfaces.usb
            or spsdk.sdp.interfaces.usb.
        :param serial: The serial number of the device.
        :param original_path: Original device path before conversion, used for hashing.
        """
        self.vid = vid
        self.pid = pid
        self.path = path
        self.product_string = product_string
        self.manufacturer_string = manufacturer_string
        self.name = name
        self.serial = serial
        self.path_hash = get_hash(original_path) if original_path else "N/A"

    def __str__(self) -> str:
        """Returns a formatted device description string.

        The method provides a human-readable representation of the USB device including
        product information, vendor/product IDs, device path, and serial number.

        :return: Multi-line formatted string with complete USB device information.
        """
        return (
            f"{self.product_string} - {self.manufacturer_string}\n"
            f"Vendor ID: 0x{self.vid:04x}\n"
            f"Product ID: 0x{self.pid:04x}\n"
            f"Path: {self.path}\n"
            f"Path Hash: {self.path_hash}\n"
            f"Name: {self.name}\n"
            f"Serial number: {self.serial}"
        )


class UUUDeviceDescription:
    """UUU device description container.

    This class provides a stable container for UUU device information that remains
    consistent across different UUU API implementations. It encapsulates USB device
    properties including identification, product details, and connection path for
    reliable device management in SPSDK operations.
    """

    def __init__(
        self,
        path: str,
        chip: str,
        pro: str,
        vid: int,
        pid: int,
        bcd: int,
        serial_no: str,
    ) -> None:
        """Initialize USB device description with device properties.

        :param path: The path to the USB device.
        :param chip: The chip of the USB device.
        :param pro: The product of the USB device.
        :param vid: The vendor ID of the USB device.
        :param pid: The product ID of the USB device.
        :param bcd: The device release number in binary-coded decimal.
        :param serial_no: The serial number of the USB device.
        """
        self.path = path
        self.chip = chip
        self.pro = pro
        self.vid = vid
        self.pid = pid
        self.bcd = bcd
        self.serial_no = serial_no

    def __str__(self) -> str:
        """Returns a formatted device description string.

        :return: Multi-line string containing device information including path, chip, product,
                 vendor ID, product ID, BCD, and serial number.
        """
        return (
            f"Path: {self.path}\n"
            f"Chip: {self.chip}\n"
            f"Product: {self.pro}\n"
            f"Vendor ID: 0x{self.vid:04x}\n"
            f"Product ID: 0x{self.pid:04x}\n"
            f"BCD: {self.bcd}\n"
            f"Serial Number: {self.serial_no}"
        )


class SDIODeviceDescription(DeviceDescription):
    """SDIO device description container.

    This class provides a standardized representation of SDIO device information
    including vendor ID, product ID, and device path. It serves as a consistent
    interface across different SDIO API implementations, ensuring compatibility
    and reliability in device identification and management within SPSDK operations.
    """

    def __init__(
        self,
        vid: int,
        pid: int,
        path: str,
    ) -> None:
        """Initialize USB device descriptor.

        Creates a new USB device descriptor with vendor ID, product ID, and device path.

        :param vid: Vendor ID of the USB device.
        :param pid: Product ID of the USB device.
        :param path: USB device path string.
        """
        self.vid = vid
        self.pid = pid
        self.path = path

    def __str__(self) -> str:
        """Returns a formatted device description string.

        :return: Text information of device including vendor ID, product ID, and path.
        """
        return (
            f"Vendor ID: 0x{self.vid:04x}\n"
            f"Product ID: 0x{self.pid:04x}\n"
            f"Path: {self.path}\n"
        )


class SIODeviceDescription(DeviceDescription):
    """LIBUSBSIO device description container.

    This class provides a structured representation of LIBUSBSIO device information,
    including device identifiers, connection details, and hardware specifications.
    It serves as a standardized interface for accessing and displaying LIBUSBSIO
    device properties within the SPSDK framework.
    """

    def __init__(self, info: LIBUSBSIO.HIDAPI_DEVICE_INFO_T) -> None:
        """Initialize USB device description from LIBUSBSIO device information.

        Creates a device description object that extracts and stores relevant
        device information including vendor/product IDs, strings, path, and
        interface details.

        :param info: LIBUSBSIO device information structure containing USB device details.
        """
        self._info = info
        self.pid = self._info.product_id
        self.vid = self._info.vendor_id
        self.manufacturer_string = self._info.manufacturer_string
        self.product_string = self._info.product_string
        self.path = convert_usb_path(self._info.path)
        self.serial_number = self._info.serial_number
        self.interface_number = self._info.interface_number
        self.release_number = self._info.release_number
        self.path_hash = get_hash(self._info.path)

    def __str__(self) -> str:
        """Get string representation of the device description.

        Returns a formatted multi-line string containing all device information including
        manufacturer, product details, identifiers, and connection parameters.

        :return: Formatted text description of the SIO device.
        """
        return (
            f"LIBUSBSIO - {self.manufacturer_string}, {self.product_string}\n"
            f"Vendor ID: 0x{self.vid:04x}\n"
            f"Product ID: 0x{self.pid:04x}\n"
            f"Path: {self.path}\n"
            f"Path Hash: {self.path_hash or 'N/A'}\n"
            f"Serial number: {self.serial_number}\n"
            f"Interface number: {self.interface_number}\n"
            f"Release number: {self.release_number}"
        )


def get_usb_device_name(
    vid: int, pid: int, device_names: Optional[dict[str, list[UsbId]]] = None
) -> list[str]:
    """Get USB device name based on VID/PID.

    Searches provided dictionary for device name based on VID/PID. If the dict
    is None, the search happens on USB_DEVICES under mboot/interfaces/usb.py and
    sdphost/interfaces/usb.py
    DESIGN REMARK: this function is not part of the USBLogicalDevice, as the
    class intention is to be just a simple container. But to help the class
    to get the required inputs, this helper method has been provided.

    :param vid: Vendor ID to search for.
    :param pid: Product ID to search for.
    :param device_names: Dictionary mapping device names to USB ID lists, defaults to None.
    :return: List of device names matching the VID/PID combination.
    """
    nxp_device_names = set()

    def find_device_names(device_names: dict[str, list[UsbId]]) -> set:
        """Find device names matching specific USB VID/PID combination.

        Searches through a dictionary of device configurations to identify all device names
        that have USB configurations matching the specified vendor ID and product ID.

        :param device_names: Dictionary mapping device names to lists of USB configurations.
        :return: Set of device names that match the USB VID/PID criteria.
        """
        dnames = set()
        for dname, usb_configs in device_names.items():
            for cfg in usb_configs:
                if cfg.vid == vid and cfg.pid == pid:
                    dnames.add(dname)
        return dnames

    if device_names:
        return list(find_device_names(device_names))
    nxp_device_names.update(find_device_names(MbootUSBInterface.get_devices()))
    nxp_device_names.update(find_device_names(SdpUSBInterface.get_devices()))
    return list(nxp_device_names)
