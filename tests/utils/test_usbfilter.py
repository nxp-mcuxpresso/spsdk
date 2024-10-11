#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
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
        b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",
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
):
    with patch("platform.system", MagicMock(return_value="Windows")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id, search_by_pid=search_by_pid)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,search_by_pid,expected", mac_use_cases)
def test_usb_match_mac(
    filter_usb_id: str, vid: str, pid: str, path: str, search_by_pid: bool, expected: bool
):
    with patch("platform.system", MagicMock(return_value="Darwin")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id, search_by_pid=search_by_pid)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,search_by_pid,expected", linux_use_cases)
def test_usb_match_linux(
    filter_usb_id: str, vid: str, pid: str, path: str, search_by_pid: bool, expected: bool
):
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
        b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000",
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
def test_usb_match_win_nxp(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
    with patch("platform.system", MagicMock(return_value="Windows")):
        usb_filter = NXPUSBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,expected", mac_use_cases_nxp)
def test_usb_match_mac_nxp(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
    with patch("platform.system", MagicMock(return_value="Darwin")):
        usb_filter = NXPUSBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id": int(vid, 0), "product_id": int(pid, 0), "path": path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize("filter_usb_id,vid,pid,path,expected", linux_use_cases_nxp)
def test_usb_match_linux_nxp(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
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
def test_device_name_win(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
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
def test_device_name_mac(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
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
def test_device_name_linux(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
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
def test_general_device_name(filter_usb_id: str, name: str, expected: bool):
    usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
    g_virtual_hid_device = {"device_name": name}

    assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id, serial, expected",
    [("1234567", "1234567", True), ("Nonsense", "1234567", False)],
)
def test_general_device_serial_number(filter_usb_id: str, serial: str, expected: bool):
    usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
    g_virtual_hid_device = {"serial_number": serial}

    assert usb_filter.compare(g_virtual_hid_device) == expected
