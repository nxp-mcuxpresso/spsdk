#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for serial communication with a target device using MBoot protocol."""

# This violation is suppressed due to differences in Win/Linux implementation of USB
# pylint: disable=E1101

import collections
import logging
import os
import platform

from struct import pack, unpack_from
from time import time
from typing import List, Tuple, Union

import hid

from ..exceptions import McuBootConnectionError

from ..commands import CmdPacket, CmdResponse, parse_cmd_response
from .base import Interface

logger = logging.getLogger('MBOOT:USB')

# os.environ['PYUSB_DEBUG'] = 'debug'
# os.environ['PYUSB_LOG_FILENAME'] = 'usb.log'

REPORT_ID = {
    # USB HID Reports
    'CMD_OUT': 0x01,
    'CMD_IN': 0x03,
    'DATA_OUT': 0x02,
    'DATA_IN': 0x04
}

########################################################################################################################
# Devices
########################################################################################################################

USB_DEVICES = {
    # NAME   | VID   | PID
    'MKL27': (0x15A2, 0x0073),
    'LPC55': (0x1FC9, 0x0021),
    'IMXRT': (0x1FC9, 0x0135),
    'MXRT20': (0x15A2, 0x0073),  # this is ID of flash-loader for RT102x
    'MXRT50': (0x15A2, 0x0073),  # this is ID of flash-loader for RT105x
    'MXRT60': (0x15A2, 0x0073),  # this is ID of flash-loader for RT106x
    'LPC55xx': (0x1FC9, 0x0020),
    'LPC551x': (0x1FC9, 0x0022),
    'RT6xx': (0x1FC9, 0x0021),
    'RT5xx': (0x1FC9, 0x0020),
    'RT6xxM': (0x1FC9, 0x0024)
}


def scan_usb(device_name: str = None) -> List[Interface]:
    """Scan connected USB devices.

    :param device_name: The specific device name (MKL27, LPC55, ...) or VID:PID
    :return: list of matching RawHid devices
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
        data_len = min(len(data) - offset, report_size - 4)
        raw_data = pack('<2BH', report_id, 0x00, data_len)
        raw_data += data[offset: offset + data_len]
        raw_data += bytes([0x00] * (report_size - len(raw_data)))
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data, offset + data_len

    @staticmethod
    def _decode_report(raw_data: bytes) -> Union[CmdResponse, bytes]:
        """Decodes the data read on USB interface.

        :param raw_data: Data received
        :type raw_data: bytes
        :return: CmdResponse object or data read
        :raises McuBootConnectionError: Transaction aborted by target
        """
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        report_id, _, plen = unpack_from('<2BH', raw_data)
        if plen == 0:
            logger.debug("Received an abort package")
            raise McuBootConnectionError('Transaction aborted')
        data = raw_data[4: 4 + plen]
        if report_id == REPORT_ID['CMD_IN']:
            return parse_cmd_response(data)
        return data

    def info(self) -> str:
        """Return information about the USB interface."""
        return f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"

    def open(self) -> None:
        """Open the interface."""
        logger.debug("Open Interface")
        try:
            self.device.open(self.vid, self.pid)
            self._opened = True
        except OSError:
            raise McuBootConnectionError(f"Unable to open device VIP={self.vid} PID={self.pid} SN='{self.sn}'")

    def close(self) -> None:
        """Close the interface."""
        logging.debug("Close Interface")
        try:
            self.device.close()
            self._opened = False
        except OSError:
            raise McuBootConnectionError(f"Unable to close device VIP={self.vid} PID={self.pid} SN='{self.sn}'")

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data on the OUT endpoint associated to the HID interfaces.

        :param packet: Data to send
        :raises ValueError: Raises an error if packet type is incorrect
        """
        if isinstance(packet, CmdPacket):
            report_id = REPORT_ID['CMD_OUT']
            data = packet.to_bytes()
        elif isinstance(packet, (bytes, bytearray)):
            report_id = REPORT_ID['DATA_OUT']
            data = packet
        else:
            raise ValueError("Packet has to be either 'CmdPacket' or 'bytes'")

        report_size = 1021
        data_index = 0
        while data_index < len(data):
            raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
            self.device.write(raw_data)

    def read(self) -> Union[CmdResponse, bytes]:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        """
        raw_data = self.device.read(1024, self.timeout)
        if platform.system() == "Linux":
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
