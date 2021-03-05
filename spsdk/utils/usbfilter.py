#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module defining a USB filtering class."""
import platform
import re

from typing import Dict, Tuple, Any


class USBDeviceFilter:
    """USB Device Filtering class.

    Create a filtering instance. This instance holds the USB ID you are insterested
    in during USB HID device search and allows you to compare, whether
    provided USB HID object is the one you are insterested in.
    The allowed format of `usb_id` string is following:

    vid - vendor ID. String holding hex or dec number.
    Hex number must be preceded by 0x or 0X. Number of characters after 0x is
    1 - 4. Mixed upper & lower case letters is allowed. e.g. "0xaB12", "0XAB12",
    "0x1", "0x0001".
    The decimal number is restrictred only to have 1 - 5 digits, e.g. "65535"
    It's allowed to set the USB filter ID to decimal number "99999", however, as
    the USB VID number is four-byte hex number (max value is 65535), this will
    lead to zero results. Leading zeros are not allowed e.g. 0001. This will
    result as invalid match.

    vid/pid - string of vendor ID & product ID separated by ':' or ','
    Same rules apply to the number format as in VID case, except, that the
    string consists of two numbers separated by ':' or ','. It's not allowed
    to mix hex and dec numbers, e.g. "0xab12:12345" is not allowed.
    Valid vid/pid strings:
    "0x12aB:0xabc", "1,99999"

    device name: see USB_DEVICES

    Windows specific:
    instance ID - String in following format "HID\\VID_<HEX>&PID_<HEX>\\<instance_id>",
    see instance ID in device manager under Windows OS.

    Linux specific:
    USB device path - HID API returns path in following form:
    '0003:0002:00'

    The first number represents the Bus, the second Device and the third interface. The Bus:Device
    number is unique so interface is not necessary and Bus:Device should be sufficient.

    The Bus:Device can be observed using 'lsusb' command. The interface can be observed using
    'lsusb -t'. lsusb returns the Bus and Device as a 3-digit number.
    It has been agreed, that the expected input is:
    <Bus in dec>#<Device in dec>, e.g. 3#11

    Mac specific:
    USB device path - HID API returns path in roughly following form:
    'IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS01@14100000/SE
    Blank RT Family @14100000/IOUSBHostInterface@0/AppleUserUSBHostHIDDevice'

    This path can be found using the 'ioreg' utility or using 'IO Hardware Registry Explorer' tool.
    However, using the system report from 'About This MAC -> System Report -> USB' a partial path
    can also be gathered. Using the name of USB device from the 'USB Device Tree' and appending
    the 'Location ID' should work. The name can be 'SE Blank RT Family' and the 'Location ID' is
    in form <hex> / <dec>, e.g. '0x14200000 / 18'.
    So the 'usb_id' name should be 'SE Blank RT Family @14200000' and the filter should be able to
    filter out such device.
    """
    # match anything starting with 0x or 0X followed by 0-9 or a-f or
    # match either 0 or decimal number not starting with zero
    __vid_regex = "0[xX][0-9a-fA-F]{1,4}|0|[1-9][0-9]{0,4}"
    # same as above, except it's a combination of two numbers separated by : or ,
    __vid_pid_regex = "0[xX][0-9a-fA-F]{1,4}(,|:)0[xX][0-9a-fA-F]{1,4}|(0|[1-9][0-9]{0,4})(,|:)(0|[1-9][0-9]{0,4})"

    def __init__(self, usb_id: str = None, nxp_device_names: Dict[str, Tuple[int, int]] = None):
        """Initialize the USB Device Filtering.

        :param usb_id: usb_id string
        :param nxp_device_names: Dictionary holding NXP device vid/pid {"device_name": [vid(int), pid(int)]}
        """
        self.usb_id = usb_id
        self.nxp_device_names = nxp_device_names or {}

    @staticmethod
    def get_vid_regex() -> str:
        """Returns the default VID regular expression."""
        return USBDeviceFilter.__vid_regex

    @staticmethod
    def get_vid_pid_regex() -> str:
        """Returns the default VID/PID regular expression."""
        return USBDeviceFilter.__vid_pid_regex

    def compare(self, usb_device_object: Any) -> bool:
        """Compares the internal `usb_id` with provided `usb_device_object`.

        :param usb_device_object: hidapi USB HID device object

        :return: True on match, False otherwise
        """
        vid_regex = self.get_vid_regex()
        vid_pid_regex = self.get_vid_pid_regex()
        vendor_id = usb_device_object["vendor_id"]
        product_id = usb_device_object["product_id"]

        # the hidapi holds the path as bytes, so we convert it to string
        usb_path = usb_device_object["path"].decode('utf-8')

        if platform.system() == 'Windows':
            # On WIN, the user has an instance ID (+ the tool expects following format):
            # 'HID\\VID_1FC9&PID_0130\\6&3B9928A5&0&0000'
            # However, the path has following format:
            # '\\\\?\\hid#vid_1fc9&pid_0130#6&1625c75b&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}'
            # There is a pattern, which matches, so we take the path and modify it
            # to match the instance ID format. We convert the path to upper case and
            # replace the hash sign with backslash
            #usb_path = usb_path.upper()
            usb_path = usb_path.replace('#', '\\')

        if platform.system() == 'Linux':
            # The user input is expected in form of <dec_num>#<dec_num>. So we
            # convert the path returned by HID API into this form so we can
            # compare it
            nums = usb_path.split(":")
            usb_path = str.format("{}#{}", int(nums[0], 16), int(nums[1], 16))

        # Determine, whether given device matches one of the expected criterion
        if self.usb_id is None:
            return True
        elif self.usb_id.casefold() in usb_path.casefold() and len(self.usb_id) > 0:
            # we check the len of usb_id, because usb_id = "" is considered
            # to be always in the string returning True, which is not expected
            # behaviour
            # the provided usb string id fully matches the instance ID
            return True
        elif re.fullmatch(vid_regex, self.usb_id) is not None:
            # the string corresponds to the vid specification, check a match
            if int(self.usb_id, 0) == vendor_id:
                return True
        elif re.fullmatch(vid_pid_regex, self.usb_id):
            # the string corresponds to the vid/pid specification, check a match
            vid_pid = re.split(":|,", self.usb_id)
            if vendor_id == int(vid_pid[0], 0) and product_id == int(vid_pid[1], 0):
                return True
        elif self.usb_id in self.nxp_device_names:
            vid, pid = self.nxp_device_names[self.usb_id]
            if vendor_id == vid and product_id == pid:
                return True
        else:
            return False

        return False
