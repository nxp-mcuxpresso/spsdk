#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for USB communication with a terget using SDP protocol."""

# This violation is suppressed due to differences in Win/Linux implementation of USB
# pylint: disable=E1101

import collections
import logging
import os
import platform

from time import time
from typing import List, Tuple, Union

import hid

from ..commands import CmdPacket, CmdResponse
from ..exceptions import SdpConnectionError
from .base import Interface

logger = logging.getLogger('SDP:USB')

# os.environ['PYUSB_DEBUG'] = 'debug'
# os.environ['PYUSB_LOG_FILENAME'] = 'usb.log'


HID_REPORT = {
    # name | id | length
    'CMD': (0x01, 1024, False),
    'DATA': (0x02, 1024, False),
    'HAB': (0x03, 4),
    'RET': (0x04, 64)
}

USB_DEVICES = {
    # NAME    | VID   | PID
    'MX6DQP': (0x15A2, 0x0054),
    'MX6SDL': (0x15A2, 0x0061),
    'MX6SL': (0x15A2, 0x0063),
    'MX6SX': (0x15A2, 0x0071),
    'MX6UL': (0x15A2, 0x007D),
    'MX6ULL': (0x15A2, 0x0080),
    'MX6SLL': (0x15A2, 0x0128),
    'MX7SD': (0x15A2, 0x0076),
    'MX7ULP': (0x1FC9, 0x0126),
    'VYBRID': (0x15A2, 0x006A),

    'MXRT20': (0x1FC9, 0x0130),
    'MXRT50': (0x1FC9, 0x0130),
    'MXRT60': (0x1FC9, 0x0135),

    'MX8MQ': (0x1FC9, 0x012B),

    'MX8QXP-A0': (0x1FC9, 0x007D),
    'MX8QM-A0': (0x1FC9, 0x0129),

    'MX8QXP': (0x1FC9, 0x012F),
    'MX8QM': (0x1FC9, 0x0129),
    'MX815': (0x1FC9, 0x013E),
    'MX865': (0x1FC9, 0x0146)
}


def scan_usb(device_name: str = None) -> List[Interface]:
    """Scan connected USB devices. Return a list of all founded devices.

    :param device_name: The specific device name (MX8QM, MX8QXP, ...) or VID:PID
    :return: List of found interfaces
    """
    devices = []

    if device_name is None:
        for _, value in USB_DEVICES.items():
            devices += RawHid.enumerate(value[0], value[1])
    else:
        if ':' in device_name:
            vid_str, pid_str = device_name.split(':')
            devices = RawHid.enumerate(int(vid_str, 0), int(pid_str, 0))
        else:
            if device_name in USB_DEVICES:
                vid = USB_DEVICES[device_name][0]
                pid = USB_DEVICES[device_name][1]
                devices = RawHid.enumerate(vid, pid)
    return devices


########################################################################################################################
# USB HID Interface Class
########################################################################################################################
class RawHid(Interface):
    """Base class for OS specific RAW HID Interface classes."""

    @property
    def name(self) -> str:
        """Get the name of the device.

        :return: Name of the device.
        """
        for name, value in USB_DEVICES.items():
            if value[0] == self.vid and value[1] == self.pid:
                return name
        return 'Unknown'

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False othervise.
        """
        return self._opened

    def __init__(self) -> None:
        """Initialize the USB interface object."""
        self._opened = False
        self.vid = 0
        self.pid = 0
        self.sn = ""
        self.vendor_name = ""
        self.product_name = ""
        self.interface_number = 0
        self.timeout = 2000
        self.device = None

    @staticmethod
    def _encode_report(report_id: int, report_size: int, data: bytes, offset: int = 0) -> Tuple[bytes, int]:
        """Encode the USB packet.

        :param report_id: ID of the report (see: HID_REPORT)
        :param report_size: Length of the report to send
        :param data: Data to send
        :param offset: offset within the 'data' bytes
        :return: Encoded bytes and length of the final report frame
        """
        data_len = min(len(data) - offset, report_size)
        raw_data = bytes([report_id])
        raw_data += data[offset: offset + data_len]
        raw_data += bytes([0x00] * (report_size - data_len))
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data, offset + data_len

    @staticmethod
    def _decode_report(raw_data: bytes) -> CmdResponse:
        """Decodes the data read on USB interface.

        :param raw_data: Data received
        :type raw_data: bytes
        :return: CmdResponse object
        """
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return CmdResponse(raw_data[0] == HID_REPORT['HAB'][0], raw_data[1:])

    def info(self) -> str:
        """Return information about the USB interface."""
        return f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"

    def conf(self, config: dict):
        """Set HID report data.

        :param config: parameters dictionary
        """
        if 'hid_ep1' in config and 'pack_size' in config:
            HID_REPORT['CMD'] = (0x01, config['pack_size'], config['hid_ep1'])
            HID_REPORT['DATA'] = (0x02, config['pack_size'], config['hid_ep1'])

    def open(self) -> None:
        """Open the interface."""
        logger.debug("Open Interface")
        try:
            self.device.open(self.vid, self.pid)
            self.device.set_nonblocking(False)
            # self.device.read(1021, 1000)
            self._opened = True
        except OSError:
            raise SdpConnectionError(f"Unable to open device VIP={self.vid} PID={self.pid} SN='{self.sn}'")

    def close(self) -> None:
        """Close the interface."""
        logging.debug("Close Interface")
        try:
            self.device.close()
            self._opened = False
        except OSError:
            raise SdpConnectionError(f"Unable to close device VIP={self.vid} PID={self.pid} SN='{self.sn}'")

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data on the OUT endpoint associated to the HID interfaces.

        :param packet: Data to send
        :raises ValueError: Raises an error if packet type is incorrect
        """
        if isinstance(packet, CmdPacket):
            report_id, report_size, hid_ep1 = HID_REPORT['CMD']
            data = packet.to_bytes()
        elif isinstance(packet, (bytes, bytearray)):
            report_id, report_size, hid_ep1 = HID_REPORT['DATA']
            data = packet
        else:
            raise ValueError("Packet has to be either 'CmdPacket' or 'bytes'")

        data_index = 0
        while data_index < len(data):
            raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
            self.device.write(raw_data)

    def read(self, length: int = None) -> CmdResponse:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        """
        raw_data = self.device.read(1024, self.timeout)
        if raw_data[0] == 0x04 and platform.system() == "Linux":
            raw_data += self.device.read(1024, self.timeout)
        return self._decode_report(bytes(raw_data))

    @staticmethod
    def enumerate(vid: int, pid: int) -> List[Interface]:
        """Get list of all connected devices which matches PyUSB.vid and PyUSB.pid.

        :param vid: USB Vendor ID
        :param pid: USB Product ID
        :return: List of interfaces found
        """
        devices = []
        all_hid_devices = hid.enumerate()

        # iterate on all devices found
        for dev in all_hid_devices:
            if dev['vendor_id'] == vid and dev['product_id'] == pid:
                new_device = RawHid()
                new_device.device = hid.device()
                new_device.vid = vid
                new_device.pid = pid
                new_device.vendor_name = dev['manufacturer_string']
                new_device.product_name = dev['product_string']
                new_device.interface_number = dev['interface_number']
                devices.append(new_device)

        return devices
