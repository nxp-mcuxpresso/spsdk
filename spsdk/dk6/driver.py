#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""DK6 Drivers backend interface."""
import logging
import time
from enum import Enum
from typing import TYPE_CHECKING, Union

from spsdk.dk6.serial_device import SerialDevice
from spsdk.exceptions import SPSDKError

logger = logging.getLogger(__name__)

DELAY_ISP_IO_TOGGLE_WAIT_MS = 100

# FTDI sequence in format PIN, BITMODE, MS_WAIT
FTDI_ISP_SEQUENCE = [
    (0xC0, 0x20, 10),
    (0xC4, 0x20, DELAY_ISP_IO_TOGGLE_WAIT_MS),
    (0xCC, 0x20, 10),
    (0x0C, 0x20, 10),
    (0x00, 0x00, 10),
]


def generate_pyftdi_url(serial_number: str, address: int = 1) -> str:
    """Generates URL for PyFTDI from serial number.

    :param serial_number: serial number from USBDeviceDescriptor
    :param address: interface number
    :return: url for PyFTDI
    """
    return f"ftdi://::{serial_number}/{address}"


class Backend(Enum):
    """Backend selection."""

    PYFTDI = 1
    PYLIBFTDI = 2
    FTD2xx = 3
    PYSERIAL = 4


class DeviceInfo:
    """Device info class.

    Contains information about the connected device
    """

    def __init__(
        self,
        device_id: Union[str, int],
        vid: int,
        pid: int,
        sn: str,
        description: str,
        address: int,
        backend: Backend,
    ):
        """Device info constructor.

        :param device_id: Device ID
        :param vid: USB VID
        :param pid: USB PID
        :param sn: Serial number
        :param description: description
        :param address: device address
        :param backend: backend
        """
        self.device_id = device_id
        self.vid = vid
        self.pid = pid
        self.sn = sn
        self.description = description
        self.address = address
        self.backend = backend

    def __str__(self) -> str:
        return (
            f"DEVICE ID: {self.device_id}, VID: {hex(self.vid) if self.vid else 'N/A'}, "
            f"PID: {hex(self.pid) if self.pid else 'N/A'}, Serial number: {self.sn}, "
            f"Description: {self.description}, Address: {self.address}, Backend: {self.backend}"
        )


if TYPE_CHECKING:
    import ftd2xx
    import pyftdi.ftdi
    import pylibftdi
    import serial

    DriverType = (
        pyftdi.ftdi.Ftdi,
        pylibftdi.Driver,
        ftd2xx.FTD2XX,
        serial.Serial,
    )
else:
    DriverType = object


# pylint: disable=import-error
class DriverInterface:
    """Interface to FTDI backends.

    Supported backends are: pyftdi, pylibftdi and ftdi2xx
    """

    def __init__(self, backend: Backend) -> None:
        """Initialize driver interface and serial interface based on backend.

        :param backend: supported backend name
        """
        self.backend = backend
        self.initialized = False
        self.dev = None
        self.driver = None

        logger.info(f"Initializing backend {backend}")

        if self.backend == Backend.PYFTDI:
            try:
                from pyftdi import ftdi
            except ImportError as e:
                raise SPSDKError(
                    "PYFTDI backend was selected, but required 'pyftdi` package is not installed. "
                    "Please install DK6 extras."
                ) from e

            self.driver = ftdi.Ftdi()
            self.dev = None

        if self.backend == Backend.PYLIBFTDI:
            try:
                from pylibftdi import Device, Driver
            except ImportError as e:
                raise SPSDKError(
                    "PYLIBFTDI backend was selected, but required 'pylibftdi` package is not installed. "
                    "Please install DK6 extras."
                ) from e

            self.dev = Device()
            self.driver = Driver()

        if self.backend == Backend.FTD2xx:
            try:
                # ruff: noqa: F401
                import ftd2xx  # pylint: disable=unused-import
            except ImportError as e:
                raise SPSDKError(
                    "FTD2xx backend was selected, but required 'ftd2xx` package is not installed. "
                    "Please install DK6 extras."
                ) from e
            except OSError as e:
                raise SPSDKError(
                    "Required 'ftd2xx` package is installed, however the underlying SO library wasn't found. "
                    "Please install libftd2xx.so (.dll, .dynlib)."
                ) from e

    def go_to_isp(self, device_id: str) -> None:
        """Send a sequence that goes to ISP mode using FTDI bitbang device."""
        logger.info("Sending bitbang sequence to ISP mode")
        if self.backend == Backend.PYFTDI:
            from pyftdi import ftdi

            url = generate_pyftdi_url(device_id)

            assert isinstance(self.driver, DriverType)
            self.driver.open_bitbang_from_url(url)
            for ins in FTDI_ISP_SEQUENCE:
                bitmode = ftdi.Ftdi.BitMode.CBUS if ins[1] == 0x20 else ftdi.Ftdi.BitMode.RESET
                self.driver.set_bitmode(ins[0], bitmode)
                time.sleep(ins[2] / 1000)

        elif self.backend == Backend.FTD2xx:
            import ftd2xx as ftd

            if self.dev is None:
                logger.info("Initializing serial first before ISP bitbang for D2XX backend")

                self.dev = ftd.open(int(device_id))
            for ins in FTDI_ISP_SEQUENCE:
                self.dev.setBitMode(ins[0], ins[1])
                time.sleep(ins[2] / 1000)
            self.dev.close()

        else:
            logger.error("Selected backend does not have method for ISP sequence")

    def list_devices(self) -> list[DeviceInfo]:
        """Returns a list of devices that are connected for selected backend.

        :return: List of devices
        """
        devices_info = []
        logger.info("Enumerating DK6 devices")
        if self.backend == Backend.PYFTDI:
            assert isinstance(self.driver, DriverType)
            devices_list = self.driver.list_devices()
            for device in devices_list:
                device_info = DeviceInfo(
                    device[0].sn,
                    device[0].vid,
                    device[0].pid,
                    device[0].sn,
                    device[0].description,
                    device[0].address,
                    self.backend,
                )
                devices_info.append(device_info)

        elif self.backend == Backend.FTD2xx:
            import ftd2xx as ftd

            device_count = ftd.createDeviceInfoList()
            for n in range(device_count):
                dev_dict = ftd.getDeviceInfoDetail(n)
                dev_info = DeviceInfo(
                    device_id=dev_dict.get("index"),
                    vid=0,
                    pid=0,
                    sn=dev_dict.get("serial"),
                    description=dev_dict.get("description"),
                    address=dev_dict.get("id"),
                    backend=self.backend,
                )
                devices_info.append(dev_info)

        elif self.backend == Backend.PYSERIAL:
            import serial.tools.list_ports

            ports = serial.tools.list_ports.comports()

            for port in ports:
                dev_info = DeviceInfo(
                    device_id=port.device,
                    vid=port.vid,
                    pid=port.pid,
                    sn=port.serial_number,
                    description=port.description,
                    address=port.location,
                    backend=self.backend,
                )
                devices_info.append(dev_info)

        else:
            logger.error("Selected backend does not implement method for listing devices")

        return devices_info

    def init_serial(self, device_id: str, baudrate: int = 115200, timeout: int = 5000) -> None:
        """Initialize serial device.

        :param device_id: device ID
        :param baudrate: UART baudrate, defaults to 115200
        :param timeout: read and write timeout, defaults to 5000 ms
        :raises SPSDKError: if invalid device_id is provided
        """
        logger.info(
            f"Initializing serial device for dev: {device_id}, baudrate: {baudrate} and timeout: {timeout}"
        )
        if self.initialized:
            logger.info("Serial already initialized, skipping initialization")
            return

        if self.backend == Backend.PYFTDI:
            import pyftdi.serialext

            timeout //= 1000
            url = generate_pyftdi_url(device_id)
            self.dev = pyftdi.serialext.serial_for_url(
                url, baudrate=baudrate, timeout=timeout, write_timeout=timeout
            )
            self.dev.reset_input_buffer()
            self.dev.reset_output_buffer()
            self.initialized = True

        elif self.backend == Backend.PYLIBFTDI:
            from pylibftdi import Device

            self.dev = Device(device_id=device_id)
            self.initialized = True

        elif self.backend == Backend.FTD2xx:
            import ftd2xx as ftd

            try:
                device_id_int = int(device_id)
            except ValueError as exc:
                raise SPSDKError("Invalid value for FTD2xx DEVICE_ID, it must be int") from exc
            self.dev = ftd.open(device_id_int)
            self.dev.resetPort()
            self.dev.setBaudRate(baudrate)
            self.dev.setTimeouts(timeout, timeout)
            self.initialized = True

        elif self.backend == Backend.PYSERIAL:
            import serial

            timeout //= 1000
            self.dev = serial.Serial(
                port=device_id,
                baudrate=baudrate,
                timeout=timeout,
                write_timeout=timeout,
            )
            self.initialized = True

    def get_serial(self) -> SerialDevice:
        """Return serial device.

        :raises SPSDKError: if serial device is not initialized
        :return: Serial device based on backend
        """
        if not self.initialized or not self.dev:
            raise SPSDKError("Serial device is not initialized")
        return self.dev

    def set_baud_rate(self, baudrate: int) -> None:
        """Set baud rate.

        :param baudrate: UART baudrate
        """
        logger.info(f"Setting baudrate to {baudrate}")
        if not self.initialized:
            logger.error("Serial not initialized")
            return

        if self.backend == Backend.PYFTDI and self.dev:
            self.dev.baudrate = baudrate

        elif self.backend == Backend.PYLIBFTDI and self.dev:
            self.dev.baudrate = baudrate

        elif self.backend == Backend.FTD2xx and self.dev:
            self.dev.setBaudRate(baudrate)

        elif self.backend == Backend.PYSERIAL and self.dev:
            self.dev.baudrate = baudrate
