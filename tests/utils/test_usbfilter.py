#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import re
from unittest.mock import MagicMock, patch

import pytest
from spsdk.utils.usbfilter import USBDeviceFilter


# test to verify, that the regular expression for vid string identification is correct
@pytest.mark.parametrize(
    "usb_id",
    [
        "0x1", # single hex[1-4] allowed
        "0X1", # preceding hex identifier 0x must be lower case
        "0x1AB4", # single hex[1-4] allowed
        "0x1aB9", # single hex[1-4] with mixed upper/lower case letters allowed
        "0", # single dec[1-5] allowed
        "99999", # single dec[1=5] allowed
    ]
)
def test_vid_regex_valid_ids(usb_id):
    assert re.fullmatch(USBDeviceFilter.get_vid_regex(), usb_id)


@pytest.mark.parametrize(
    "usb_id",
    [
        "", # empty string not allowed
        "0x", # at least one character after hex identifier must be provided
        "0x1ABCD", # hex number of len 5 not allowed
        "0x1234,0x1111", # single value allowed only (not vid,pid combination)
        "0x1234:0x1111", # single value allowed only (not vid:pid combination)
        "11,11", # single value allowed only (not vid,pid combination)
        "11:11", # single value allowed only (not vid:pid combination)
        "abcd", # preceding 0x not allowed
    ]
)
def test_vid_regex_invalid_ids(usb_id):
    assert re.fullmatch(USBDeviceFilter.get_vid_regex(), usb_id) is None


# test to verify, that the regular expression for vid_pid string identification is correct
@pytest.mark.parametrize(
    "usb_id",
    [
        "1,1", # allowed fromat dec[1-5],dec[1-5]
        "1:1", # allowed format dec[1-5]:dec[1-5]
        "0xa,0x1", # allowed format hex[1-4],hex[1-4]
        "0xa:0xB", # allowed format hex[1-4]:hex[1-4]
        "0x1234:0xabcd", # allowed format hex[1-4]:hex[1-4]
        "99999,1", # allowed format dec[1-5],dec[1-5]
    ]
)
def test_vid_pid_regex_valid_ids(usb_id):
    assert re.fullmatch(USBDeviceFilter.get_vid_pid_regex(), usb_id)


@pytest.mark.parametrize(
    "usb_id",
    [
        "0x1,a", # not allowed to mix hex and dec numbers in vid:pid combination
        "a,0x1", # not allowed to mix hex and dec numbers in vid:pid combination
        "0x1234", # not allowed to have a single number (vid:pid is required)
        "0xa", # not allowed to have a single number (vid:pid is required)
        "12345", # not allowed to have a single number (vid:pid is required)
        "123456:12345", # dec number must be 1 - 5 digits
        ":12345" # dec number must be 1 - 5 digits
        "0x:0xabCD", # hex number must be 1 - 4 digits
        "ab12:0x1a2b", # not allowed to use hex without preceding 0x
    ]
)
def test_vid_pid_regex_invalid_ids(usb_id):
    assert re.fullmatch(USBDeviceFilter.get_vid_pid_regex(), usb_id) is None


common_use_cases = [
    ("0x1234", "0x1234", "0x0", b"//", True), # match in vid (hex form)
    ("4660", "0x1234", "0x0", b"//", True), # match in vid (dec form)
    ("0x1", "0x1234", "0x0", b"//", False), # no match - vid differs
    ("1", "0x1234", "0x0", b"//", False), # no match - vid differs
    ("", "0x1234", "0x0", b"//", False), # no match - empty filtering string
    ("0x1234,0xabcd", "0x1234", "0xabcd", b"//", True), # match in vid,pid combination
    ("0x1234:0xabcd", "0x1234", "0xabcd", b"//", True), # match in vid:pid combination
    ("1,12345", "1", "12345", b"//", True), # match in vid,pid combination
    ("1:12345", "1", "12345", b"//", True), # match in vid,pid combination
]

win_use_cases = common_use_cases + [
    ("HID\\VID_413C&PID_301A\\A&2D263B2&0&0000", "0x413c", "0x301a",
     b"\\\\?\\hid#vid_413c&pid_301a#a&2d263b2&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}", True),
]

mac_use_cases = common_use_cases + [
    ("SE Blank RT Family @14200000", "0x413c", "0x301a",
     b"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS02@14200000/SE Blank RT Family @14200000", True),
]

linux_use_cases = [
    ("0x1234", "0x1234", "0x0", b"0:0", True), # match in vid (hex form)
    ("4660", "0x1234", "0x0", b"0:0", True), # match in vid (dec form)
    ("0x1", "0x1234", "0x0", b"0:0", False), # no match - vid differs
    ("1", "0x1234", "0x0", b"0:0", False), # no match - vid differs
    ("", "0x1234", "0x0", b"0:0", False), # no match - empty filtering string
    ("0x1234,0xabcd", "0x1234", "0xabcd", b"0:0", True), # match in vid,pid combination
    ("0x1234:0xabcd", "0x1234", "0xabcd", b"0:0", True), # match in vid:pid combination
    ("1,12345", "1", "12345", b"0:0", True), # match in vid,pid combination
    ("1:12345", "1", "12345", b"0:0", True), # match in vid,pid combination
    ("3#11", "0x413c", "0x301a", b"0003:000b:00", True),
    ("2#2", "0x413c", "0x301a", b"0003:000b:00", False)
]
@pytest.mark.parametrize(
    "filter_usb_id,vid,pid,path,expected",
    win_use_cases
)
def test_usb_match_win(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
    with patch('platform.system', MagicMock(return_value="Windows")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id":int(vid, 0), "product_id":int(pid, 0), "path":path}

        assert usb_filter.compare(g_virtual_hid_device) == expected


@pytest.mark.parametrize(
    "filter_usb_id,vid,pid,path,expected",
    mac_use_cases
)
def test_usb_match_mac(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
    with patch('platform.system', MagicMock(return_value="Darwin")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id":int(vid, 0), "product_id":int(pid, 0), "path":path}

        assert usb_filter.compare(g_virtual_hid_device) == expected

@pytest.mark.parametrize(
    "filter_usb_id,vid,pid,path,expected",
    linux_use_cases
)
def test_usb_match_linux(filter_usb_id: str, vid: str, pid: str, path: str, expected: bool):
    with patch('platform.system', MagicMock(return_value="Linux")):
        usb_filter = USBDeviceFilter(usb_id=filter_usb_id)
        g_virtual_hid_device = {"vendor_id":int(vid, 0), "product_id":int(pid, 0), "path":path}

        assert usb_filter.compare(g_virtual_hid_device) == expected
