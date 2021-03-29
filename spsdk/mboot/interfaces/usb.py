#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2016-2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for serial communication with a target device using MBoot protocol."""

import logging

from struct import pack, unpack_from
from typing import Sequence, Union

import hid
from spsdk.utils.usbfilter import USBDeviceFilter

from ..commands import CmdPacket, CmdResponse, parse_cmd_response
from ..exceptions import McuBootConnectionError, McuBootDataAbortError
from .base import Interface

logger = logging.getLogger('MBOOT:USB')

# import os
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
    'RT5xx_A': (0x1FC9, 0x0020),
    'RT5xx_B': (0x1FC9, 0x0023),
    'RT5xx_C': (0x1FC9, 0x0023),
    'RT5xx': (0x1FC9, 0x0023),
    'RT6xxM': (0x1FC9, 0x0024)
}


def scan_usb(device_name: str = None) -> Sequence[Interface]:
    """Scan connected USB devices.

    :param device_name: see USBDeviceFilter classes constructor for usb_id specification
    :return: list of matching RawHid devices
    """
    usb_filter = USBDeviceFilter(usb_id=device_name, nxp_device_names=USB_DEVICES)
    return RawHid.enumerate(usb_filter)


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
        return self.device is not None and self._opened

    def __init__(self) -> None:
        """Initialize the USB interface object."""
        super().__init__()
        self._opened = False
        self.vid = 0
        self.pid = 0
        self.serial_number = ""
        self.vendor_name = ""
        self.product_name = ""
        self.interface_number = 0
        self.timeout = 2000
        self.path = ""
        self.device = None

    @staticmethod
    def _encode_report(report_id: int, data: bytes) -> bytes:
        """Encode the USB packet.

        :param report_id: ID of the report (see: HID_REPORT)
        :param data: Data to send
        :return: Encoded bytes and length of the final report frame
        """
        raw_data = pack('<2BH', report_id, 0x00, len(data))
        raw_data += data
        logger.debug(f"OUT[{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        return raw_data

    @staticmethod
    def _decode_report(raw_data: bytes) -> Union[CmdResponse, bytes]:
        """Decodes the data read on USB interface.

        :param raw_data: Data received
        :type raw_data: bytes
        :return: CmdResponse object or data read
        :raises McuBootDataAbortError: Transaction aborted by target
        """
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        report_id, _, plen = unpack_from('<2BH', raw_data)
        if plen == 0:
            raise McuBootDataAbortError()
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
            assert self.device
            self.device.open_path(self.path)
            self._opened = True
        except OSError:
            raise McuBootConnectionError(
                f"Unable to open device VIP={self.vid} PID={self.pid} SN='{self.serial_number}'"
            )

    def close(self) -> None:
        """Close the interface."""
        logging.debug("Close Interface")
        try:
            assert self.device
            self.device.close()
            self._opened = False
        except OSError:
            raise McuBootConnectionError(
                f"Unable to close device VIP={self.vid} PID={self.pid} SN='{self.serial_number}'"
            )

    def write(self, packet: Union[CmdPacket, bytes]) -> None:
        """Write data on the OUT endpoint associated to the HID interfaces.

        :param packet: Data to send
        :raises ValueError: Raises an error if packet type is incorrect
        :raises McuBootConnectionError: Raises an error if device is not openned for writing
        """
        if not self.is_opened:
            raise McuBootConnectionError(f"Device is openned for writing")

        if isinstance(packet, CmdPacket):
            report_id = REPORT_ID['CMD_OUT']
            data = packet.to_bytes(padding=False)
        elif isinstance(packet, (bytes, bytearray)):
            report_id = REPORT_ID['DATA_OUT']
            data = packet
        else:
            raise ValueError("Packet has to be either 'CmdPacket' or 'bytes'")

        raw_data = self._encode_report(report_id, data)
        assert self.device
        self.device.write(raw_data)

    def read(self) -> Union[CmdResponse, bytes]:
        """Read data on the IN endpoint associated to the HID interface.

        :return: Return CmdResponse object.
        :raises McuBootConnectionError: Raises an error if device is not openned for reading
        :raises TimeoutError: Time-out
        """
        if not self.is_opened:
            raise McuBootConnectionError(f"Device is not openned for reading")

        assert self.device
        raw_data = self.device.read(1024, self.timeout)
        if not raw_data:
            logger.error(self.device.error())
            raise TimeoutError()
        # NOTE: uncomment the following when using KBoot/Flashloader v2.1 and older
        # import platform
        # if platform.system() == "Linux":
        #     raw_data += self.device.read(1024, self.timeout)
        return self._decode_report(bytes(raw_data))

    @staticmethod
    def enumerate(usb_device_filter: USBDeviceFilter) -> Sequence[Interface]:
        """Get list of all connected devices which matches PyUSB.vid and PyUSB.pid.

        :param usb_device_filter: USBDeviceFilter object
        :return: List of interfaces found
        """
        devices = []
        all_hid_devices = hid.enumerate()

        # iterate on all devices found
        for dev in all_hid_devices:
            if usb_device_filter.compare(dev) is True:
                new_device = RawHid()
                new_device.device = hid.device()
                new_device.vid = dev["vendor_id"]
                new_device.pid = dev["product_id"]
                new_device.vendor_name = dev['manufacturer_string']
                new_device.product_name = dev['product_string']
                new_device.interface_number = dev['interface_number']
                new_device.path = dev["path"]
                devices.append(new_device)

        return devices
