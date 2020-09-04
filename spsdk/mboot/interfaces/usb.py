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
from struct import pack, unpack_from
from time import time
from typing import List, Tuple, Union

from spsdk.exceptions import SPSDKError

from ..commands import CmdPacket, CmdResponse, parse_cmd_response
from .base import Interface

logger = logging.getLogger('MBOOT:USB')

# os.environ['PYUSB_DEBUG'] = 'debug'
# os.environ['PYUSB_LOG_FILENAME'] = 'usb.log'

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
# USB HID Interface Base Class
########################################################################################################################

REPORT_ID = {
    # USB HID Reports
    'CMD_OUT': 0x01,
    'CMD_IN': 0x03,
    'DATA_OUT': 0x02,
    'DATA_IN': 0x04
}


class RawHidBase(Interface):
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
        super().__init__()
        self._opened = False
        self.vid = 0
        self.pid = 0
        self.vendor_name = ""
        self.product_name = ""
        self.timeout = 2000

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
        :raises SPSDKError: Transaction aborted by target
        """
        logger.debug(f"IN [{len(raw_data)}]: {', '.join(f'{b:02X}' for b in raw_data)}")
        report_id, _, plen = unpack_from('<2BH', raw_data)
        if plen == 0:
            logger.debug("Received an abort package")
            raise SPSDKError('Transaction aborted')
        data = raw_data[4: 4 + plen]
        if report_id == REPORT_ID['CMD_IN']:
            return parse_cmd_response(data)
        return data

    def info(self) -> str:
        """Return information about the USB interface."""
        return f"{self.product_name:s} (0x{self.vid:04X}, 0x{self.pid:04X})"


########################################################################################################################
# USB Interface Classes
########################################################################################################################
if os.name == "nt":
    try:
        import pywinusb.hid as hid
    except:
        raise Exception("PyWinUSB is required on a Windows Machine")


    class RawHid(RawHidBase):
        """Provides basic functions to access a USB HID device using pywinusb."""

        def __init__(self) -> None:
            """Initialize the USB interface object."""
            super().__init__()
            # Vendor page and usage_id = 2
            self.report: List[hid.core.HidReport] = []
            # deque used here instead of synchronized Queue
            # since read speeds are ~10-30% faster and are
            # comparable to a based list implementation.
            self.rcv_data: collections.deque = collections.deque()
            self.device: hid.HidDevice = None

        # handler called when a report is received
        def rx_handler(self, data: bytes) -> None:
            """Handler is called when a new USB report (data) is received.

            :param data: Data received by the USB stack
            """
            # logging.debug("rcv: %s", data[1:])
            self.rcv_data.append(data)

        def open(self) -> None:
            """Open the interface."""
            logger.debug("Open Interface")
            self.device.set_raw_data_handler(self.rx_handler)
            self.device.open(shared=False)
            self._opened = True

        def close(self) -> None:
            """Close the interface."""
            logger.debug("Close Interface")
            self.device.close()
            self._opened = False

        def write(self, packet: Union[CmdPacket, bytes]) -> None:
            """Write data on the OUT endpoint associated to the HID interface.

            :param packet: HID packet data
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

            data_index = 0
            # TODO: find alternative method to get the report size
            # pylint: disable=protected-access
            report_size = self.report[report_id - 1]._HidReport__raw_report_size
            while data_index < len(data):
                raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                self.report[report_id - 1].send(raw_data)

        def read(self) -> Union[CmdResponse, bytes]:
            """Read data on the IN endpoint associated to the HID interfaces.

            :return: Response to the last command
            :raises TimeoutError: Exception caused by time-out
            """
            start = time()
            while len(self.rcv_data) == 0:
                if ((time() - start) * 1000) > self.timeout:
                    raise TimeoutError()

            raw_data = self.rcv_data.popleft()
            return self._decode_report(bytes(raw_data))

        @staticmethod
        def enumerate(vid: int, pid: int) -> List[Interface]:
            """Returns all the connected devices which matches PyWinUSB.vid/PyWinUSB.pid.

            :param vid: USB Vendor ID
            :param pid: USB Product ID
            :return: List of interfaces found
            """
            targets: List[Interface] = []
            all_devices = hid.find_all_hid_devices()

            # find devices with good vid/pid
            for dev in all_devices:
                if (dev.vendor_id == vid) and (dev.product_id == pid):
                    try:
                        dev.open(shared=False)
                        report = dev.find_output_reports()

                        if report:
                            new_target = RawHid()
                            new_target.report = report
                            new_target.vendor_name = dev.vendor_name
                            new_target.product_name = dev.product_name
                            new_target.vid = dev.vendor_id
                            new_target.pid = dev.product_id
                            new_target.device = dev
                            new_target.device.set_raw_data_handler(new_target.rx_handler)
                            targets.append(new_target)

                    except hid.HIDError as e:
                        logger.error(f"Receiving Exception: {str(e)}")
                    finally:
                        dev.close()

            return targets


else:
    try:
        import usb.core
        import usb.util
    except:
        raise Exception("PyUSB is required on a Linux Machine")


    class RawHid(RawHidBase):
        """Provides basic functions to access a USB HID device using pyusb."""

        def __init__(self) -> None:
            """Initialize the USB interface object."""
            super().__init__()
            self.ep_out = None
            self.ep_in = None
            self.device = None
            self.interface_number = -1

        def open(self) -> None:
            """Open the interface."""
            logger.debug("Open Interface")
            self._opened = True

        def close(self) -> None:
            """Close the interface."""
            logger.debug("Close Interface")
            self._opened = False
            try:
                if self.device:
                    usb.util.dispose_resources(self.device)
            except usb.core.HIDError:
                pass

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

            data_index = 0
            if self.ep_out:
                report_size = self.ep_out.wMaxPacketSize
                while data_index < len(data):
                    raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                    self.ep_out.write(raw_data)

            else:
                bm_request_type = 0x21  # ------ # Host to device request of type Class of Recipient Interface
                bm_request = 0x09  # ----------- # Set_REPORT: HID class-specific request for transferring data over EP0
                w_value = 0x200 + report_id  # - # Issuing an OUT report with specified ID
                w_index = self.interface_number  # Interface number for HID
                report_size = 36  # TODO: get the value from descriptor
                while data_index < len(data):
                    raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                    self.device.ctrl_transfer(bm_request_type, bm_request, w_value, w_index, raw_data)

        def read(self) -> Union[CmdResponse, bytes]:
            """Read data on the IN endpoint associated to the HID interface.

            :return: Return CmdResponse object.
            """
            # TODO: test if self.ep_in.wMaxPacketSize is accessible in all Linux distributions
            raw_data = self.ep_in.read(self.ep_in.wMaxPacketSize, self.timeout)
            # TODO: why is the code commented-out? rawdata = self.ep_in.read(36, timeout)
            return self._decode_report(raw_data)

        @staticmethod
        def enumerate(vid: int, pid: int) -> List[Interface]:
            """Get list of all connected devices which matches PyUSB.vid and PyUSB.pid.

            :param vid: USB Vendor ID
            :param pid: USB Product ID
            :return: List of interfaces found
            """
            targets: List[Interface] = []
            # find all devices matching the vid/pid specified
            all_devices = usb.core.find(find_all=True, idVendor=vid, idProduct=pid)

            if not all_devices:
                logger.debug("No device connected")
                return targets

            # iterate on all devices found
            for dev in all_devices:
                interface = None
                interface_number = -1

                # get active config
                config = dev.get_active_configuration()

                # iterate on all interfaces:
                for interface in config:
                    if interface.bInterfaceClass == 0x03:  # HID Interface
                        interface_number = interface.bInterfaceNumber
                        break

                if interface is None or interface_number == -1:
                    continue

                try:
                    if dev.is_kernel_driver_active(interface_number):
                        dev.detach_kernel_driver(interface_number)
                except usb.core.USBError as e:
                    logger.debug(str(e))

                try:
                    dev.set_configuration()
                    dev.reset()

                except usb.core.USBError as e:
                    logger.debug(f"Cannot set configuration for the device: {str(e)}")

                ep_in, ep_out = None, None
                for endpoint in interface:
                    if endpoint.bEndpointAddress & 0x80:
                        ep_in = endpoint
                    else:
                        ep_out = endpoint

                if not ep_in:
                    logger.error('Endpoints not found')
                    return targets

                new_target = RawHid()
                new_target.ep_in = ep_in
                new_target.ep_out = ep_out
                new_target.device = dev
                new_target.vid = vid
                new_target.pid = pid
                new_target.interface_number = interface_number
                new_target.vendor_name = usb.util.get_string(dev, 1).strip('\0')
                new_target.product_name = usb.util.get_string(dev, 2).strip('\0')
                targets.append(new_target)

            return targets
