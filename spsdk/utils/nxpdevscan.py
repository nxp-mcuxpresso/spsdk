#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""NXP USB Device Scanner API."""

import array
import logging
import platform
import struct
from typing import Any, Optional

from libusbsio import LIBUSBSIO_Exception, usbsio
from serial import SerialException
from serial.tools.list_ports import comports
from serial.tools.list_ports_common import ListPortInfo

from spsdk.exceptions import (
    SPSDKConnectionError,
    SPSDKError,
    SPSDKPermissionError,
    SPSDKUnsupportedOperation,
)
from spsdk.mboot.interfaces.sdio import MbootSdioInterface
from spsdk.mboot.interfaces.uart import MbootUARTInterface
from spsdk.sdp.interfaces.uart import SdpUARTInterface
from spsdk.sdp.sdp import SDP
from spsdk.uboot.spsdk_uuu import SPSDKUUU
from spsdk.uboot.uboot import UbootSerial
from spsdk.utils.devicedescription import (
    SDIODeviceDescription,
    SIODeviceDescription,
    UartDeviceDescription,
    USBDeviceDescription,
    UUUDeviceDescription,
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


def search_nxp_sdio_devices() -> list[SDIODeviceDescription]:
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


def search_nxp_usb_devices(extend_vid_list: Optional[list] = None) -> list[USBDeviceDescription]:
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


def search_uuu_usb_devices() -> list[UUUDeviceDescription]:
    """Searches all UUU compatible USB devices.

    :return: list of USBDeviceDescription corresponding to UUU devices
    """
    uuu = SPSDKUUU()
    devices = []

    def usb_device_callback(
        path: bytes, chip: bytes, pro: bytes, vid: int, pid: int, bcd: int, serial_no: bytes, p: Any
    ) -> int:
        """Callback function for uuu_for_each_devices.

        :param path: The path to the USB device.
        :param chip: The chip of the USB device.
        :param pro: The product of the USB device.
        :param vid: The vendor ID of the USB device.
        :param pid: The product ID of the USB device.
        :param bcd: BDC.
        :param serial_no: The serial number of the USB device.
        :param p: A pointer to additional data.
        :return: 0 on success.
        """
        description = UUUDeviceDescription(
            path.decode("utf-8"),
            chip.decode("utf-8"),
            pro.decode("utf-8"),
            vid,
            pid,
            bcd,
            serial_no.decode("utf-8"),
        )

        devices.append(description)
        return 0

    uuu.for_each_devices(usb_device_callback)
    return devices


def is_real_tty_device(device: str) -> bool:
    """Check if a /dev/ttyS* device is a real serial device using ioctl.

    Check only for Linux.
    Check is based on ioctl TIOCGSERIAL. If the device is not a real serial device,
    the ioctl will return PORT_UNKNOWN (0).

    :param device: The device path.
    :return: True if the device is a real serial device, False otherwise.
    """
    if platform.system() != "Linux":
        raise SPSDKUnsupportedOperation("This function is only supported on Linux.")
    import fcntl  # pylint: disable=import-error

    if not device.startswith("/dev/ttyS"):
        # We are interested only in /dev/ttyS* devices, not /dev/ttyUSB* or /dev/ttyACM*
        return True

    # Define the TIOCGSERIAL ioctl command
    TIOCGSERIAL = 0x541E
    try:
        with open(device, "rb") as fd:
            serial_info = array.array("i", [0] * 32)
            fcntl.ioctl(fd, TIOCGSERIAL, serial_info, True)  # type: ignore[attr-defined]
            if serial_info[0] != 0:  # PORT_UNKNOWN is 0
                return True
            return False
    except Exception:
        return False


def filter_uart_devices(ports: list[ListPortInfo], real_devices: bool) -> list[ListPortInfo]:
    """Filter UART devices.

    :ports: ListPortInfo from pyserial
    :real_devices: Scan for real devices using ioctl TIOCGSERIAL.
    """
    # on macOS, we need to filter out ports that are not serial ports
    if platform.system() == "Darwin":
        ports = [
            port
            for port in ports
            if port.device.startswith("/dev/cu.usb") or port.device.startswith("/dev/tty.usb")
        ]

    if platform.system() == "Linux" and real_devices:
        # filter out non-serial devices
        ports = [port for port in ports if is_real_tty_device(port.device)]

    return ports


def search_nxp_uart_devices(
    scan: bool = True,
    all_devices: bool = True,
    scan_uboot: bool = True,
    timeout: int = 50,
    real_devices: bool = False,
) -> list[UartDeviceDescription]:
    """Returns a list of all NXP devices connected via UART.

    :scan: whether to scan for mboot and SDP devices
    :all_devices: whether to return all devices or only NXP devices
    :scan_uboot: whether to scan for U-Boot console devices
    :timeout: timeout for UART scan in ms
    :real_devices: Check if the device is real using ioctl TIOCGSERIAL.
    :retval: list of UartDeviceDescription devices from devicedescription module
    """
    retval = []

    if all_devices:
        # Get all available COM ports on target PC
        ports = comports()
    else:
        # Get only NXP devices
        ports = [port for port in comports() if port.vid in NXP_USB_DEVICE_VIDS]

    ports = filter_uart_devices(ports, real_devices)

    if not scan:
        return [
            UartDeviceDescription(
                name=port.device,
                dev_type=("NXP UART device" if port.vid in NXP_USB_DEVICE_VIDS else "UART device"),
            )
            for port in ports
        ]

    # Iterate over every com port we have and check, whether mboot or sdp responds
    for port in ports:
        if MbootUARTInterface.scan(port=port.device, timeout=timeout):
            uart_dev = UartDeviceDescription(name=port.device, dev_type="mboot device")
            retval.append(uart_dev)
            continue

        # Seems the port is not mboot, let's try SDP protocol
        # The SDP protocol is on uart interface, so opening just the port is not
        # sufficient, to say, that the interface is SDP compared to mboot, where
        # ping command must be sent.
        # So we create an SDP interface and try to read the status code. If
        # we get a response, we are connected to an SDP device.
        sdp_com = None
        try:
            device = SerialDevice(port=port.device, timeout=timeout)
            sdp_com = SDP(SdpUARTInterface(device))
            if sdp_com.read_status() is not None:
                uart_dev = UartDeviceDescription(name=port.device, dev_type="SDP device")
                retval.append(uart_dev)
                continue
        except (SPSDKConnectionError, SPSDKPermissionError, struct.error) as e:
            logger.debug(
                f"Exception {type(e).__name__} occurred while reading status via SDP. \
Arguments: {e.args}"
            )
        finally:
            if isinstance(sdp_com, SDP):
                sdp_com.close()
        # Another option is U-Boot console interface
        if not scan_uboot:
            continue
        try:
            logger.debug(f"Checking if port {port.device} is U-boot serial console")
            uboot = UbootSerial(port=port.device, timeout=1, interrupt_autoboot=False)
            if uboot.is_serial_console_open():
                uart_dev = UartDeviceDescription(name=port.device, dev_type="U-Boot console")
                retval.append(uart_dev)
        except (SPSDKConnectionError, SPSDKPermissionError, SerialException) as e:
            logger.debug(
                f"Exception {type(e).__name__} occurred while trying to find U-Boot console. \
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


def search_libusbsio_devices() -> list[SIODeviceDescription]:
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
