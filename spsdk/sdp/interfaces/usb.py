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
from time import time
from typing import List, Tuple, Union

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
# USB Interface Base Class
########################################################################################################################
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
            self.report = []
            # deque used here instead of synchronized Queue
            # since read speeds are ~10-30% faster and are
            # comparable to a based list implementation.
            self.rcv_data = collections.deque()
            self.device = None

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
            """Write data on the OUT endpoint associated to the HID interfaces.

            :param packet: HID packet data
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
                self.report[report_id - 1].send(raw_data)

        def read(self) -> CmdResponse:
            """Read data on the IN endpoint associated to the HID interfaces.

            :return: Response to the last command
            :raises SdpConnectionError: Exception caused by time-out
            """
            start = time()
            while len(self.rcv_data) == 0:
                if ((time() - start) * 1000) > self.timeout:
                    raise SdpConnectionError("Read timed out")

            raw_data = self.rcv_data.popleft()
            return self._decode_report(bytes(raw_data))

        @staticmethod
        def enumerate(vid: int, pid: int) -> List[Interface]:
            """Returns all the connected devices which matches PyWinUSB.vid/PyWinUSB.pid.

            :param vid: USB Vendor ID
            :param pid: USB Product ID
            :return: List of interfaces found
            """
            targets = []
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
                            new_target.vendor_name = dev.vendor_name.strip()
                            new_target.product_name = dev.product_name.strip()
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

elif os.name == "posix":
    try:
        import usb.core
        import usb.util
    except:
        raise ImportError("PyUSB is required on a Linux Machine")

    class RawHid(RawHidBase):
        """Provides basic functions to access a USB HID device using pyusb."""
        vid = 0
        pid = 0
        interface_number = 0

        def __init__(self) -> None:
            """Initialize the USB interface object."""
            super().__init__()
            self.device = None
            self._opened = False

        def open(self) -> None:
            """Open the interface."""
            logger.debug("Open Interface")
            # self.device.open()
            try:
                if self.device.is_kernel_driver_active(0):
                    self.device.detach_kernel_driver(0)
                self._opened = True
            except usb.core.HIDError as e:
                logging.warning(str(e))

        def close(self) -> None:
            """Close the interface."""
            logging.debug("Close Interface")
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
                report_id, report_size, hid_ep1 = HID_REPORT['CMD']
                data = packet.to_bytes()
            elif isinstance(packet, (bytes, bytearray)):
                report_id, report_size, hid_ep1 = HID_REPORT['DATA']
                data = packet
            else:
                raise ValueError("Packet has to be either 'CmdPacket' or 'bytes'")

            bm_request_type = 0x21  # ------ # Host to device request of type Class of Recipient Interface
            bm_request = 0x09  # ----------- # Set_REPORT (HID class-specific request for transferring data over EP0)
            w_value = 0x200 + report_id  # - # Issuing an OUT report with specified ID
            w_index = self.interface_number  # Interface number for HID

            data_index = 0
            while data_index < len(data):
                raw_data, data_index = self._encode_report(report_id, report_size, data, data_index)
                if hid_ep1:
                    self.device.write(0x1, raw_data)
                else:
                    self.device.ctrl_transfer(bm_request_type, bm_request, w_value, w_index, raw_data)

        def read(self) -> CmdResponse:
            """Read data on the IN endpoint associated to the HID interface.

            :return: Return CmdResponse object.
            """
            raw_data = self.device.read(1 | 0x80, 1024, self.timeout)
            return self._decode_report(raw_data)

        @staticmethod
        def enumerate(vid: int, pid: int) -> List[Interface]:
            """Get list of all connected devices which matches PyUSB.vid and PyUSB.pid.

            :param vid: USB Vendor ID
            :param pid: USB Product ID
            :return: List of interfaces found
            :raises SdpConnectionError: Propagating exception from underlying USB module
            """
            devices = []
            all_hid_devices = usb.core.find(find_all=True, idVendor=vid, idProduct=pid)

            # iterate on all devices found
            for dev in all_hid_devices:

                try:
                    new_device = RawHid()
                    new_device.device = dev
                    new_device.vid = dev.idVendor
                    new_device.pid = dev.idProduct
                    new_device.vendor_name = usb.util.get_string(dev, 1).strip('\0')
                    new_device.product_name = usb.util.get_string(dev, 2).strip('\0')
                    new_device.interface_number = 0
                    devices.append(new_device)
                except usb.core.USBError as e:
                    logging.debug(e)
                    raise SdpConnectionError(e)

            return devices

else:
    raise ImportError("No USB backend found")
