#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USB device filtering utilities tests.

This module contains comprehensive test cases for USB device filtering functionality
across different operating systems (Windows, macOS, Linux). Tests cover both generic
USB device filtering and NXP-specific device filtering scenarios, ensuring proper USB
device identification and filtering behavior across supported platforms.
"""

from unittest.mock import MagicMock, patch

import pytest

from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.utils.usbfilter import NXPUSBDeviceFilter, USBDeviceFilter

common_use_cases = [
    ("0x1234", "0x1234", "0x0", b"//", False, True),  # match in vid (hex form)
    ("4660", "0x1234", "0x0", b"//", False, True),  # match in vid (dec form)
    ("0x1", "0x1234", "0x0", b"//", False, False),  # no match - vid differs
    ("1", "0x1234", "0x0", b"//", False, False),  # no match - vid differs
    ("", "0x1234", "0x0", b"//", False, False),  # no match - empty filtering string
    ("0x1234,0xabcd", "0x1234", "0xabcd", b"//", False, True),  # match in vid,pid combination
    ("0x1234:0xabcd", "0x1234", "0xabcd", b"//", False, True),  # match in vid:pid combination
    ("1,12345", "1", "12345", b"//", False, True),  # match in vid,pid combination
    ("1:12345", "1", "12345", b"//", False, True),  # match in vid,pid combination
    (None, "0x1fc9", "0x0001", b"//", False, True),  # match all devices if usb_id is none
    ("0x1234", "0x1fc9", "0x1234", b"//", True, True),  # match pid if VID is NXP VID
    (
        "0x1234",
        "0x1234",
        "0x1234",
        b"//",
        True,
        True,
    ),  # match pid if VID is not NXP VID - generic USB filter
]

win_use_cases = common_use_cases + [
    (
        "HID\\VID_413C&PID_301A\\A&2D263B2&0&0000",
        "0x413c",
        "0x301a",
        b"\\\\?\\hid#vid_413c&pid_301a#a&2d263b2&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}",
        False,
        True,
    ),
]

mac_use_cases = common_use_cases + [
    (
        "SE Blank RT Family @14200000",
        "0x413c",
        "0x301a",
        b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",  # pylint: disable=line-too-long
        False,
        True,
    ),
]

linux_use_cases = [
    ("0x1234", "0x1234", "0x0", b"0:0", False, True),  # match in vid (hex form)
    ("4660", "0x1234", "0x0", b"0:0", False, True),  # match in vid (dec form)
    ("0x1", "0x1234", "0x0", b"0:0", False, False),  # no match - vid differs
    ("1", "0x1234", "0x0", b"0:0", False, False),  # no match - vid differs
    ("", "0x1234", "0x0", b"0:0", False, False),  # no match - empty filtering string
    ("0x1234,0xabcd", "0x1234", "0xabcd", b"0:0", False, True),  # match in vid,pid combination
    ("0x1234:0xabcd", "0x1234", "0xabcd", b"0:0", False, True),  # match in vid:pid combination
    ("1,12345", "1", "12345", b"0:0", False, True),  # match in vid,pid combination
    ("1:12345", "1", "12345", b"0:0", False, True),  # match in vid,pid combination
    ("3#11", "0x413c", "0x301a", b"0003:000b:00", False, True),
    ("2#2", "0x413c", "0x301a", b"0003:000b:00", False, False),
]


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,search_by_pid,expected", win_use_cases)
def test_usb_match_win(
    filter_usb_id: str, vid: str, pid: str, path: str, search_by_pid: bool, expected: bool
) -> None:
    """Test USB device filtering on Windows platform.

    This test verifies that the USBDeviceFilter correctly matches USB devices
    on Windows systems by comparing filter criteria against device properties.
    The test uses mocking to simulate Windows platform detection.

    :param filter_usb_id: USB identifier string used for device filtering
    :param vid: Vendor ID as string (supports hex format with 0x prefix)
    :param pid: Product ID as string (supports hex format with 0x prefix)
    :param path: Device path string for USB device identification
    :param search_by_pid: Flag indicating whether to search by product ID
    :param expected: Expected boolean result of the filter comparison
    """
    with patch("platform.system", MagicMock(return_value="Windows")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id, search_by_pid=search_by_pid)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,search_by_pid,expected", mac_use_cases)
def test_usb_match_mac(
    filter_usb_id: str, vid: str, pid: str, path: str, search_by_pid: bool, expected: bool
) -> None:
    """Test USB device filtering on macOS platform.

    This test verifies that the USBDeviceFilter correctly matches USB devices
    on macOS (Darwin) platform based on vendor ID, product ID, and device path.
    The test uses mocking to simulate the macOS environment.

    :param filter_usb_id: USB device identifier string for filtering
    :param vid: Vendor ID as string (supports hex format with 0x prefix)
    :param pid: Product ID as string (supports hex format with 0x prefix)
    :param path: USB device path string
    :param search_by_pid: Flag to enable searching by product ID only
    :param expected: Expected boolean result of the comparison
    """
    with patch("platform.system", MagicMock(return_value="Darwin")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id, search_by_pid=search_by_pid)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,search_by_pid,expected", linux_use_cases)
def test_usb_match_linux(
    filter_usb_id: str, vid: str, pid: str, path: str, search_by_pid: bool, expected: bool
) -> None:
    """Test USB device filtering on Linux platform.

    This test verifies that the USBDeviceFilter correctly matches USB devices
    on Linux systems based on vendor ID, product ID, and path criteria.

    :param filter_usb_id: USB ID string used to initialize the filter
    :param vid: Vendor ID string (can be hex or decimal format)
    :param pid: Product ID string (can be hex or decimal format)
    :param path: USB device path string
    :param search_by_pid: Flag indicating whether to search by product ID
    :param expected: Expected boolean result of the filter comparison
    """
    with patch("platform.system", MagicMock(return_value="Linux")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id, search_by_pid=search_by_pid)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


common_use_cases_nxp = [
    ("0x1234", "0x1234", "0x0", b"//", False),  # match in pid (hex form, VID expected one of NXP)
    ("4660", "0x1234", "0x0", b"//", False),  # match in pid (dec form, VID expected one of NXP)
    ("0x1", "0x1234", "0x0", b"//", False),  # no match - vid differs
    ("1", "0x1fc9", "0x0", b"//", False),  # no match - pid differs
    ("", "0x1fc9", "0x0", b"//", True),  # match - This is NXP device
    ("0x1234,0xabcd", "0x1234", "0xabcd", b"//", True),  # match in vid,pid combination
    ("0x1234:0xabcd", "0x1234", "0xabcd", b"//", True),  # match in vid:pid combination
    ("1,12345", "1", "12345", b"//", True),  # match in vid,pid combination
    ("1:12345", "1", "12345", b"//", True),  # match in vid,pid combination
    (None, "0x1fc9", "0x0001", b"//", True),  # match all devices if usb_id is none
    (
        None,
        "0x1111",
        "0x0001",
        b"//",
        False,
    ),  # no match - there is no specific usb_id and it is not NXP device
    ("0x1234", "0x1fc9", "0x1234", b"//", True),  # match pid if VID is NXP VID
    (
        "0x1234",
        "0x1234",
        "0x1234",
        b"//",
        False,
    ),  # don't match pid if VID is not NXP VID - NXP specific USB filter
]

win_use_cases_nxp = common_use_cases_nxp + [
    (
        "HID\\VID_413C&PID_301A\\A&2D263B2&0&0000",
        "0x413c",
        "0x301a",
        b"\\\\?\\hid#vid_413c&pid_301a#a&2d263b2&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}",
        True,
    ),
]

mac_use_cases_nxp = common_use_cases_nxp + [
    (
        "SE Blank RT Family @14200000",
        "0x413c",
        "0x301a",
        b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",  # pylint: disable=line-too-long
        True,
    ),
]

linux_use_cases_nxp = [
    ("0x1234", "0x1234", "0x0", b"0:0", False),  # match in pid (hex form, vid expected one of NXP)
    ("4660", "0x1234", "0x0", b"0:0", False),  # match in pid (dec form, vid expected one of NXP)
    ("0x1", "0x1234", "0x0", b"0:0", False),  # no match - pid differs
    ("1", "0x1234", "0x0", b"0:0", False),  # no match - pid differs
    ("", "0x1234", "0x0", b"0:0", False),  # no match - empty filtering string
    ("0x1234,0xabcd", "0x1234", "0xabcd", b"0:0", True),  # match in vid,pid combination
    ("0x1234:0xabcd", "0x1234", "0xabcd", b"0:0", True),  # match in vid:pid combination
    ("1,12345", "1", "12345", b"0:0", True),  # match in vid,pid combination
    ("1:12345", "1", "12345", b"0:0", True),  # match in vid,pid combination
    ("3#11", "0x413c", "0x301a", b"0003:000b:00", True),
    ("2#2", "0x413c", "0x301a", b"0003:000b:00", False),
]


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,expected", win_use_cases_nxp)
def test_usb_match_win_nxp(
    filter_usb_id: str, vid: str, pid: str, path: str, expected: bool
) -> None:
    """Test USB device matching on Windows platform with NXP filter.

    This test verifies that the NXPUSBDeviceFilter correctly matches USB devices
    on Windows platform by comparing vendor ID, product ID, and device path
    against the filter criteria.

    :param filter_usb_id: USB ID string used to initialize the NXP USB device filter.
    :param vid: Vendor ID string (can be hex or decimal format).
    :param pid: Product ID string (can be hex or decimal format).
    :param path: USB device path string.
    :param expected: Expected boolean result of the filter comparison.
    """
    with patch("platform.system", MagicMock(return_value="Windows")):
        usb_filter = NXPUSBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,expected", mac_use_cases_nxp)
def test_usb_match_mac_nxp(
    filter_usb_id: str, vid: str, pid: str, path: str, expected: bool
) -> None:
    """Test USB device filtering on macOS with NXP USB device filter.

    This test verifies that the NXPUSBDeviceFilter correctly matches or rejects
    USB devices on macOS (Darwin) platform based on the provided filter criteria
    and device properties.

    :param filter_usb_id: USB ID filter string to configure the NXPUSBDeviceFilter
    :param vid: Vendor ID string (can be hex or decimal format)
    :param pid: Product ID string (can be hex or decimal format)
    :param path: USB device path string
    :param expected: Expected boolean result of the filter comparison
    """
    with patch("platform.system", MagicMock(return_value="Darwin")):
        usb_filter = NXPUSBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,expected", linux_use_cases_nxp)
def test_usb_match_linux_nxp(
    filter_usb_id: str, vid: str, pid: str, path: str, expected: bool
) -> None:
    """Test USB device matching on Linux platform with NXP USB filter.

    This test verifies that the NXPUSBDeviceFilter correctly matches or rejects
    USB devices on Linux systems based on the provided filter criteria and device
    characteristics.

    :param filter_usb_id: USB ID filter string used to create the NXPUSBDeviceFilter.
    :param vid: Vendor ID string (supports hex format with 0x prefix).
    :param pid: Product ID string (supports hex format with 0x prefix).
    :param path: USB device path string.
    :param expected: Expected boolean result of the filter comparison.
    """
    with patch("platform.system", MagicMock(return_value="Linux")):
        usb_filter = NXPUSBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id, vid, pid, path, expected",
    [
        ("lpc55s36", "0x1FC9", "0x0025", b"//", True),
        ("Nonsense", "0x1FC9", "0x0025", b"//", False),
    ],
)
def test_device_name_win(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool) -> None:
    """Test device name filtering on Windows platform.

    This test verifies that the NXPUSBDeviceFilter correctly identifies devices
    on Windows by comparing a virtual HID device against the filter criteria.
    The test mocks the platform system to return "Windows" and validates the
    filter's compare method behavior.

    :param filter_usb_id: USB ID string used to initialize the device filter
    :param vid: Vendor ID as string (supports hex format with 0x prefix)
    :param pid: Product ID as string (supports hex format with 0x prefix)
    :param path: Device path string for the virtual HID device
    :param expected: Expected boolean result from the filter comparison
    """
    with patch("platform.system", MagicMock(return_value="Windows")):
        usb_filter = NXPUSBDeviceFilter(
            usb_id=filter_usb_id, nxp_device_names=MbootUSBInterface.get_devices()
        )
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id, vid, pid, path, expected",
    [
        ("lpc55s36", "0x1FC9", "0x0025", b"//", True),
        ("Nonsense", "0x1FC9", "0x0025", b"//", False),
    ],
)
def test_device_name_mac(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool) -> None:
    """Test device name filtering functionality on macOS platform.

    This test verifies that the NXPUSBDeviceFilter correctly identifies and filters
    USB devices based on device names when running on macOS (Darwin). It mocks the
    platform system to simulate macOS environment and tests the filter's compare
    method against a virtual HID device with specified vendor ID, product ID, and path.

    :param filter_usb_id: USB identifier string used for device filtering
    :param vid: Vendor ID as string (supports hex format with 0x prefix)
    :param pid: Product ID as string (supports hex format with 0x prefix)
    :param path: Device path identifier for the virtual HID device
    :param expected: Expected boolean result of the filter comparison
    """
    with patch("platform.system", MagicMock(return_value="Darwin")):
        usb_filter = NXPUSBDeviceFilter(
            usb_id=filter_usb_id, nxp_device_names=MbootUSBInterface.get_devices()
        )
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id, vid, pid, path, expected",
    [
        ("lpc55s36", "0x1FC9", "0x0025", b"0:0", True),
        ("Nonsense", "0x1FC9", "0x0025", b"0:0", False),
    ],
)
def test_device_name_linux(
    filter_usb_id: str, vid: str, pid: str, path: str, expected: bool
) -> None:
    """Test device name filtering functionality on Linux platform.

    This test verifies that the NXPUSBDeviceFilter correctly identifies and filters
    USB devices based on the provided USB ID when running on a Linux system. It uses
    a mocked platform system call and virtual HID device to simulate the filtering process.

    :param filter_usb_id: USB ID string used for device filtering
    :param vid: Vendor ID as string (supports hex format with 0x prefix)
    :param pid: Product ID as string (supports hex format with 0x prefix)
    :param path: Device path identifier for the virtual HID device
    :param expected: Expected boolean result of the filtering comparison
    """
    with patch("platform.system", MagicMock(return_value="Linux")):
        usb_filter = NXPUSBDeviceFilter(
            usb_id=filter_usb_id, nxp_device_names=MbootUSBInterface.get_devices()
        )
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id, name, expected",
    [("MKL27", "MKL27", True), ("Nonsense", "MKL27", False)],
)
def test_general_device_name(filter_usb_id: str, name: str, expected: bool) -> None:
    """Test USB device filter with general device name matching.

    This test verifies that the USBDeviceFilter correctly compares a device
    with a given device name against the specified USB ID filter criteria.

    :param filter_usb_id: USB ID string used to create the filter
    :param name: Device name to be tested against the filter
    :param expected: Expected boolean result of the comparison
    """
    usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
    g_virtual_hid_device = {"device_name": name}

    assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id, serial, expected",
    [("1234567", "1234567", True), ("Nonsense", "1234567", False)],
)
def test_general_device_serial_number(filter_usb_id: str, serial: str, expected: bool) -> None:
    """Test USB device filter with serial number matching.

    Verifies that the USB device filter correctly matches or rejects devices
    based on their serial numbers when compared against the filter criteria.

    :param filter_usb_id: USB ID string used to create the device filter
    :param serial: Serial number of the virtual HID device to test against
    :param expected: Expected boolean result of the comparison operation
    """
    usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
    g_virtual_hid_device = {"serial_number": serial}

    assert usb_filter.compare(g_virtual_hid_device) == expected
