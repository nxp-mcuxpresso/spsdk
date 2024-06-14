#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP USB Device Scanner API."""


import logging
from typing import List, Optional

from libusbsio import LIBUSBSIO_Exception, usbsio
from serial.tools.list_ports import comports

from spsdk.exceptions import SPSDKConnectionError, SPSDKError
from spsdk.mboot.interfaces.sdio import MbootSdioInterface
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.sdp.interfaces.uart import SdpUARTInterface
from spsdk.sdp.sdp import SDP
from spsdk.utils.devicedescription import (
    SDIODeviceDescription,
    SIODeviceDescription,
    UartDeviceDescription,
    USBDeviceDescription,
    convert_usb_path,
    get_usb_device_name,
)
from spsdk.utils.interfaces.device.serial_device import SerialDevice

NXP_USB_DEVICE_VIDS = [
    0x1FC9,
    0x15A2,
]

NXP_SDIO_DEVICE_PATHS = [
    "/dev/mcu-sdio",
]

logger = logging.getLogger(__name__)


def search_nxp_sdio_devices() -> List[SDIODeviceDescription]:
    """Searches all NXP SDIO devices based on their device path.

    :return: list of SDIODeviceDescription corresponding to NXP devices
    """
    nxp_sdio_devices = []

    search_path = NXP_SDIO_DEVICE_PATHS

    for path in search_path:
        sdio_device = MbootSdioInterface.scan(device_path=path)
        if len(sdio_device) > 0:
            sdio_dev = SDIODeviceDescription(
                vid=sdio_device[0].device.vid,
                pid=sdio_device[0].device.pid,
                path=sdio_device[0].device.path,
            )
            nxp_sdio_devices.append(sdio_dev)
            continue

    return nxp_sdio_devices


def search_nxp_usb_devices(extend_vid_list: Optional[list] = None) -> List[USBDeviceDescription]:
    """Searches all NXP USB devices based on their Vendor ID.

    :extend_vid_list: list of VIDs, to extend the default NXP VID list (int)
    :return: list of USBDeviceDescription corresponding to NXP devices
    """
    libusbsio_logger = logging.getLogger("libusbsio")
    sio = usbsio(loglevel=libusbsio_logger.getEffectiveLevel())
    all_usb_devices = sio.HIDAPI_Enumerate()
    nxp_usb_devices = []

    search_vids = NXP_USB_DEVICE_VIDS

    if extend_vid_list is not None:
        search_vids = list(set(search_vids) | set(extend_vid_list))

    for usb_device in all_usb_devices:
        for nxp_vid in search_vids:
            if nxp_vid == usb_device["vendor_id"]:
                # We found our device, let's create container for it
                vid = usb_device["vendor_id"]
                pid = usb_device["product_id"]
                path = convert_usb_path(usb_device["path"])
                product_string = usb_device["product_string"]
                manufacturer_string = usb_device["manufacturer_string"]
                name = " | ".join(get_usb_device_name(vid, pid, None))
                serial = usb_device["serial_number"]
                usb_dev = USBDeviceDescription(
                    vid,
                    pid,
                    path,
                    product_string,
                    manufacturer_string,
                    name,
                    serial,
                    usb_device["path"],
                )

                nxp_usb_devices.append(usb_dev)
                break

    return nxp_usb_devices


def search_nxp_uart_devices() -> List[UartDeviceDescription]:
    """Returns a list of all NXP devices connected via UART.

    :retval: list of UartDeviceDescription devices from devicedescription module
    """
    retval = []

    # Get all available COM ports on target PC
    ports = [port.device for port in comports()]

    # Iterate over every com port we have and check, whether mboot or sdp responds
    for port in ports:
        if MbootUARTInterface.scan(port=port, timeout=50):
            uart_dev = UartDeviceDescription(name=port, dev_type="mboot device")
            retval.append(uart_dev)
            continue

        # Seems the port is not mboot, let's try SDP protocol
        # The SDP protocol is on uart interface, so opening just the port is not
        # sufficient, to say, that the interface is SDP compared to mboot, where
        # ping command must be sent.
        # So we create an SDP interface and try to read the status code. If
        # we get a response, we are connected to an SDP device.
        try:
            device = SerialDevice(port=port, timeout=50)
            sdp_com = SDP(SdpUARTInterface(device))
            if sdp_com.read_status() is not None:
                uart_dev = UartDeviceDescription(name=port, dev_type="SDP device")
                retval.append(uart_dev)
        except SPSDKConnectionError as e:
            logger.debug(
                f"Exception {type(e).__name__} occurred while reading status via SDP. \
Arguments: {e.args}"
            )

    return retval


# This function has been left for potential future uses. At the moment it's
# not clear, how do we identify different devices with SDP protocol, as
# in the company, there are so many different MCU's from NXP and Freescale
# with different MCU identification options, if any...
# def parse_sim_sdid(sim_sdid: int) -> Dict:
#     """Converts the content of SIM_SDID register into string.

#     :sim_sdid: the value of SIM_SDID register
#     :retval: {"family_id": int, "subfamily_id": int, "series_id": int, "rev_id": int}
#     """
#     retval = {}
#     retval["family_id"] = (sim_sdid >> 28) & 0xF
#     retval["subfamily_id"] = (sim_sdid >> 24) & 0xF
#     retval["series_id"] = (sim_sdid >> 20) & 0xF
#     retval["rev_id"] = (sim_sdid >> 12) & 0xF
#     return retval


def search_libusbsio_devices() -> List[SIODeviceDescription]:
    """Returns a list of all LIBUSBSIO devices.

    :retval: list of UartDeviceDescription devices from devicedescription module
    :raises SPSDKError: In any case of LIBUSBSIO problems.
    """
    retval = []
    try:
        libusbsio_logger = logging.getLogger("libusbsio")
        sio = usbsio(loglevel=libusbsio_logger.getEffectiveLevel())
        for i in range(sio.GetNumPorts()):
            info = sio.GetDeviceInfo(i)
            if not info:
                raise SPSDKError("Cannot retrieve the Device Information.")
            retval.append(SIODeviceDescription(info))
    except (LIBUSBSIO_Exception, SPSDKError) as exc:
        raise SPSDKError(f"LIBUSBSIO search devices fails: [{str(exc)}]") from exc

    return retval
