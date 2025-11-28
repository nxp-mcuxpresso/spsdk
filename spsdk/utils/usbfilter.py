#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USB device filtering utilities.

This module provides functionality for filtering and identifying USB devices,
with specialized support for NXP USB devices. It includes classes for creating
device filters based on various USB properties and NXP-specific device identification.
"""

import platform
import re
from typing import Any, Optional

from spsdk.utils.database import UsbId
from spsdk.utils.misc import get_hash


class USBDeviceFilter:
    """USB device filtering utility for cross-platform device identification.

    This class provides filtering capabilities for USB HID devices across different operating
    systems. It parses various USB identifier formats including VID/PID pairs, platform-specific
    device paths, and instance IDs to enable precise device matching during enumeration.

    Supported USB ID formats:

    VID or PID - Vendor ID or product ID as hex or decimal number:
    - Hex: "0x1234", "0XAB12", "0x1" (1-4 chars after 0x, case insensitive)
    - Decimal: "4660", "65535" (1-5 digits, no leading zeros except "0")
    - Single number defaults to VID unless search_by_pid=True

    VID/PID pairs - Two numbers separated by ':' or ',':
    - "0x1fc9:0x0025", "1234,5678"
    - Both numbers must use same format (hex or decimal)

    Platform-specific formats:

    Windows - Instance ID from Device Manager:
    - "HID\\VID_<HEX>&PID_<HEX>\\<instance_id>"

    Linux - Bus and device numbers from lsusb:
    - "<bus>#<device>" format (e.g., "3#11")
    - Bus:Device numbers are decimal, interface not required

    macOS - IOService device path or partial path:
    - Full: "IOService:/AppleACPIPlatformExpert/PCI0@0/..."
    - Partial: "SE Blank RT Family @14200000" (device name + location ID)

    The filter supports both vendor ID and product ID based filtering, with configurable
    search modes for single number inputs.
    """

    def __init__(
        self,
        usb_id: Optional[str] = None,
        search_by_pid: bool = False,
    ):
        """Initialize the USB Device Filtering.

        :param usb_id: USB identifier string (VID or PID depending on search_by_pid flag).
        :param search_by_pid: If True, usb_id is treated as PID number, otherwise as VID.
        """
        self.usb_id = usb_id
        self.search_by_pid = search_by_pid

    def compare(self, usb_device_object: dict[str, Any]) -> bool:
        """Compare internal USB ID with provided USB device object.

        The provided USB ID during initialization may be VID or PID, VID/PID pair,
        or a path. The method performs matching against various device attributes
        including vendor ID, product ID, serial number, device name, and USB path.

        :param usb_device_object: Libusbsio/HID_API device object dictionary containing
                                 device information such as vendor_id, product_id,
                                 serial_number, device_name, and path
        :return: True if device matches the filter criteria, False otherwise
        """
        # Determine, whether given device matches one of the expected criterion
        if self.usb_id is None:
            return True

        vendor_id = usb_device_object.get("vendor_id")
        product_id = usb_device_object.get("product_id")
        serial_number = usb_device_object.get("serial_number")
        device_name = usb_device_object.get("device_name")
        # the Libusbsio/HID_API holds the path as bytes, so we convert it to string
        usb_path_raw = usb_device_object.get("path")

        if usb_path_raw:
            if self.usb_id == get_hash(usb_path_raw):
                return True
            usb_path = self.convert_usb_path(usb_path_raw)
            if self._is_path(usb_path=usb_path):
                return True

        if self._is_vid_or_pid(vid=vendor_id, pid=product_id):
            return True

        if vendor_id and product_id and self._is_vid_pid(vid=vendor_id, pid=product_id):
            return True

        if serial_number and self.usb_id.casefold() == serial_number.casefold():
            return True

        if device_name and self.usb_id.casefold() == device_name.casefold():
            return True

        return False

    def _is_path(self, usb_path: str) -> bool:
        """Check if USB path matches the internal USB ID.

        The method performs a case-insensitive substring comparison to determine if the
        internal usb_id is contained within the provided USB path. An empty usb_id is
        treated as no match.

        :param usb_path: USB path to be compared with internal USB ID.
        :return: True if USB ID matches the path, False otherwise.
        """
        # we check the len of usb_id, because usb_id = "" is considered
        # to be always in the string returning True, which is not expected
        # behavior
        # the provided usb string id fully matches the instance ID
        usb_id = self.usb_id or ""
        if usb_id.casefold() in usb_path.casefold() and len(usb_id) > 0:
            return True

        return False

    def _is_vid_or_pid(self, vid: Optional[int], pid: Optional[int]) -> bool:
        """Check if USB ID matches given vendor ID or product ID.

        The method validates the USB ID format using regex and compares it against
        the provided VID or PID based on the search mode configuration.

        :param vid: Vendor ID to match against, can be None.
        :param pid: Product ID to match against, can be None.
        :return: True if USB ID matches the specified VID or PID, False otherwise.
        """
        # match anything starting with 0x or 0X followed by 0-9 or a-f or
        # match either 0 or decimal number not starting with zero
        # this regex is the same for vid and pid => xid
        xid_regex = "0[xX][0-9a-fA-F]{1,4}|0|[1-9][0-9]{0,4}"
        usb_id = self.usb_id or ""
        if re.fullmatch(xid_regex, usb_id) is not None:
            # the string corresponds to the vid/pid specification, check a match
            if self.search_by_pid and pid:
                if int(usb_id, 0) == pid:
                    return True
            elif vid:
                if int(usb_id, 0) == vid:
                    return True

        return False

    def _is_vid_pid(self, vid: int, pid: int) -> bool:
        """Check if USB ID corresponds to VID/PID pair and matches provided values.

        The method validates if the stored USB ID string matches the VID/PID format
        (either hexadecimal with 0x prefix or decimal) and compares it with the
        provided vendor and product IDs.

        :param vid: Vendor ID to compare against the USB ID.
        :param pid: Product ID to compare against the USB ID.
        :return: True if USB ID matches VID/PID format and values, False otherwise.
        """
        # match anything starting with 0x or 0X followed by 0-9 or a-f or
        # match either 0 or decimal number not starting with zero
        # Above pattern is combined to match a pair corresponding to vid/pid.
        vid_pid_regex = "0[xX][0-9a-fA-F]{1,4}(,|:)0[xX][0-9a-fA-F]{1,4}|(0|[1-9][0-9]{0,4})(,|:)(0|[1-9][0-9]{0,4})"
        usb_id = self.usb_id or ""
        if re.fullmatch(vid_pid_regex, usb_id):
            # the string corresponds to the vid/pid specification, check a match
            vid_pid = re.split(":|,", usb_id)
            if vid == int(vid_pid[0], 0) and pid == int(vid_pid[1], 0):
                return True

        return False

    @staticmethod
    def convert_usb_path(hid_api_usb_path: bytes) -> str:
        """Convert USB device path from HID API format to OS-observable format.

        Converts Libusbsio/HID_API USB device paths into platform-specific string formats
        that can be observed from the operating system. The conversion handles Windows,
        Linux, and macOS platforms differently based on their respective USB path conventions.
        Note: This function is designed specifically for Libusbsio/HID_API paths and may
        fail or provide incorrect results if used with paths from other USB APIs.

        :param hid_api_usb_path: Raw USB device path bytes from Libusbsio/HID_API
        :return: Platform-specific USB device path string, empty string for unsupported OS
        """
        if platform.system() == "Windows":
            device_manager_path = hid_api_usb_path.decode("utf-8").upper()
            device_manager_path = device_manager_path.replace("#", "\\")
            result = re.search(r"\\\\\?\\(.+?)\\{", device_manager_path)
            if result:
                device_manager_path = result.group(1)

            return device_manager_path

        if platform.system() == "Linux":
            # we expect the path in form of <bus>#<device>, Libusbsio/HID_API returns
            # <bus>:<device>:<interface>
            linux_path = hid_api_usb_path.decode("utf-8")
            linux_path_parts = linux_path.split(":")

            if len(linux_path_parts) > 1:
                linux_path = str.format(
                    "{}#{}", int(linux_path_parts[0], 16), int(linux_path_parts[1], 16)
                )

            return linux_path

        if platform.system() == "Darwin":
            return hid_api_usb_path.decode("utf-8")

        return ""


class NXPUSBDeviceFilter(USBDeviceFilter):
    """NXP USB Device Filter for SPSDK operations.

    Extension of the generic USB device filter class to support filtering based on NXP devices.
    Modifies the way single number filtering is handled - when a single value is provided, it
    checks if the VID is within NXP's vendor ID range, maintaining compatibility with legacy
    tooling that expected PID-based filtering.

    :cvar NXP_VIDS: List of official NXP vendor IDs for device identification.
    """

    NXP_VIDS = [0x1FC9, 0x15A2, 0x0471, 0x0D28]

    def __init__(
        self,
        usb_id: Optional[str] = None,
        nxp_device_names: Optional[dict[str, list[UsbId]]] = None,
    ):
        """Initialize the USB Device Filtering.

        :param usb_id: USB device identifier string for filtering specific device.
        :param nxp_device_names: Dictionary mapping NXP device names to their USB identifiers,
            format: {"device_name": [UsbId objects]}.
        """
        super().__init__(usb_id=usb_id, search_by_pid=True)
        self.nxp_device_names = nxp_device_names or {}

    def compare(self, usb_device_object: Any) -> bool:
        """Compare USB device with internal USB ID and NXP device registry.

        Extends the comparison by USB names - dictionary of device name and
        corresponding VID/PID. Falls back to checking if device is any NXP device
        when no specific USB ID is configured.

        :param usb_device_object: USB HID device object containing vendor_id and product_id
        :return: True if device matches internal USB ID or is recognized NXP device, False otherwise
        """
        vendor_id = usb_device_object["vendor_id"]
        product_id = usb_device_object["product_id"]

        if self.usb_id:
            if super().compare(usb_device_object=usb_device_object):
                return True

            return self._is_nxp_device_name(vendor_id, product_id)

        return self._is_nxp_device(vendor_id)

    def _is_vid_or_pid(self, vid: Optional[int], pid: Optional[int]) -> bool:
        """Check if the device matches NXP vendor ID and optionally product ID.

        This method validates that the vendor ID belongs to NXP's registered VIDs
        before delegating to the parent class for further validation.

        :param vid: Vendor ID to check against NXP VIDs, None if not specified.
        :param pid: Product ID to check, None if not specified.
        :return: True if vid is valid NXP VID and passes parent validation, False otherwise.
        """
        if vid and vid in NXPUSBDeviceFilter.NXP_VIDS:
            return super()._is_vid_or_pid(vid, pid)

        return False

    def _is_nxp_device_name(self, vid: int, pid: int) -> bool:
        """Check if device with given VID/PID matches NXP device name.

        This method verifies whether the provided vendor ID and product ID combination
        corresponds to a known NXP device based on the current USB ID filter.

        :param vid: Vendor ID to check.
        :param pid: Product ID to check.
        :return: True if the VID/PID matches a known NXP device, False otherwise.
        """
        assert isinstance(self.usb_id, str)
        if self.usb_id in self.nxp_device_names:
            for usb_cfg in self.nxp_device_names[self.usb_id]:
                if usb_cfg.vid == vid and usb_cfg.pid == pid:
                    return True
        return False

    @staticmethod
    def _is_nxp_device(vid: int) -> bool:
        """Check if a vendor ID belongs to NXP.

        This method verifies whether the provided vendor ID is in the list of known
        NXP vendor IDs.

        :param vid: Vendor ID to check.
        :return: True if the vendor ID belongs to NXP, False otherwise.
        """
        return vid in NXPUSBDeviceFilter.NXP_VIDS
