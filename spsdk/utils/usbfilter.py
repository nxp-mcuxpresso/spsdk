#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module defining a USB filtering class."""
import platform
import re
from typing import Any, Dict, Optional, Tuple


class USBDeviceFilter:
    """Generic USB Device Filtering class.

    Create a filtering instance. This instance holds the USB ID you are interested
    in during USB HID device search and allows you to compare, whether
    provided USB HID object is the one you are interested in.
    The allowed format of `usb_id` string is following:

    vid or pid - vendor ID or product ID. String holding hex or dec number.
    Hex number must be preceded by 0x or 0X. Number of characters after 0x is
    1 - 4. Mixed upper & lower case letters is allowed. e.g. "0xaB12", "0XAB12",
    "0x1", "0x0001".
    The decimal number is restrictred only to have 1 - 5 digits, e.g. "65535"
    It's allowed to set the USB filter ID to decimal number "99999", however, as
    the USB VID number is four-byte hex number (max value is 65535), this will
    lead to zero results. Leading zeros are not allowed e.g. 0001. This will
    result as invalid match.

    The user may provide a single number as usb_id. In such a case the number
    may represent either VID or PID. By default, the filter expects this number
    to be a VID. In rare cases the user may want to filter based on PID.
    Initialize the `search_by_pid` parameter to True in such cases.

    vid/pid - string of vendor ID & product ID separated by ':' or ','
    Same rules apply to the number format as in VID case, except, that the
    string consists of two numbers separated by ':' or ','. It's not allowed
    to mix hex and dec numbers, e.g. "0xab12:12345" is not allowed.
    Valid vid/pid strings:
    "0x12aB:0xabc", "1,99999"

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

    def __init__(
        self,
        usb_id: str = None,
        search_by_pid: bool = False,
    ):
        """Initialize the USB Device Filtering.

        :param usb_id: usb_id string
        :param search_by_pid: if true, expects usb_id to be a PID number, VID otherwise.
        """
        self.usb_id = usb_id
        self.search_by_pid = search_by_pid

    def compare(self, usb_device_object: Dict[str, Any]) -> bool:
        """Compares the internal `usb_id` with provided `usb_device_object`.

        The provided USB ID during initialization may be VID or PID, VID/PID pair,
        or a path. See private methods for details.

        :param usb_device_object: Libusbsio/HID_API device object (dictionary)

        :return: True on match, False otherwise
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
            usb_path = (
                usb_path_raw.decode("utf-8")
                if isinstance(usb_path_raw, (bytes, bytearray))
                else usb_path_raw
            )
            if platform.system() == "Windows":
                # On WIN, the user has an instance ID (+ the tool expects following format):
                # 'HID\\VID_1FC9&PID_0130\\6&3B9928A5&0&0000'
                # However, the path has following format:
                # '\\\\?\\hid#vid_1fc9&pid_0130#6&1625c75b&0&0000#{4d1e55b2-f16f-11cf-88cb-001111000030}'
                # There is a pattern, which matches, so we take the path and modify it
                # to match the instance ID format. We convert the path to upper case and
                # replace the hash sign with backslash
                # usb_path = usb_path.upper()
                usb_path = usb_path.replace("#", "\\")

            if platform.system() == "Linux":
                # The user input is expected in form of <dec_num>#<dec_num>. So we
                # convert the path returned by Libusbsio/HID_API into this form so we can
                # compare it. Alternatively, the input is the real device path,
                # like '/dev/hidraw0' - in this case, just leave it as it is.
                nums = usb_path.split(":")
                if len(nums) >= 2:
                    usb_path = str.format("{}#{}", int(nums[0], 16), int(nums[1], 16))
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
        """Compares the internal usb_id with provided path.

        If the path is a substring of the usb_id, this is considered as a match
        and True is returned.

        :param usb_path: path to be compared with usd_id.
        :return: true on a match, false otherwise.
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
        """If usb_id corresponds to VID/PID pair, comapres it with provided vid/pid.

        :param vid: vendor ID to compare.
        :param pid: product ID to compare.
        :return: true on a match, false otherwise.
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


class NXPUSBDeviceFilter(USBDeviceFilter):
    """NXP Device Filtering class.

    Extension of the generic USB device filter class to support filtering
    based on NXP devices. Modifies the way, how single number is handled.
    By default, if single value is provided, it's content is expected to be VID.
    However, legacy tooling were expecting PID, so from this perspective if
    a single number is provided, we expect that VID is out of range NXP_VIDS.
    """

    NXP_VIDS = [0x1FC9, 0x15A2]

    def __init__(
        self,
        usb_id: str = None,
        nxp_device_names: Dict[str, Tuple[int, int]] = None,
    ):
        """Initialize the USB Device Filtering.

        :param usb_id: usb_id string
        :param nxp_device_names: Dictionary holding NXP device vid/pid {"device_name": [vid(int), pid(int)]}
        """
        super().__init__(usb_id=usb_id, search_by_pid=True)
        self.nxp_device_names = nxp_device_names or {}

    def compare(self, usb_device_object: Any) -> bool:
        """Compares the internal `usb_id` with provided `usb_device_object`.

        Extends the comparison by USB names - dictionary of device name and
        corresponding VID/PID.

        :param usb_device_object: lpcusbsio USB HID device object

        :return: True on match, False otherwise
        """
        vendor_id = usb_device_object["vendor_id"]
        product_id = usb_device_object["product_id"]

        is_valid_id = super().compare(usb_device_object=usb_device_object)

        if is_valid_id:
            return True

        if self._is_nxp_device_name(vendor_id, product_id):
            return True

        return False

    def _is_vid_or_pid(self, vid: Optional[int], pid: Optional[int]) -> bool:
        if vid and vid in NXPUSBDeviceFilter.NXP_VIDS:
            return super()._is_vid_or_pid(vid, pid)

        return False

    def _is_nxp_device_name(self, vid: int, pid: int) -> bool:
        if self.usb_id in self.nxp_device_names:
            vendor_id, product_id = self.nxp_device_names[self.usb_id]
            if vendor_id == vid and product_id == pid:
                return True
        return False
