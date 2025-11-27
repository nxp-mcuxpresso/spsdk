#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""DK6 driver backend interface for device communication.

This module provides the core driver infrastructure for DK6 devices, including
backend abstraction, device information handling, and communication interfaces.
It supports multiple backend types and provides utilities for device discovery
and connection management.
"""

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

    :param serial_number: Serial number from USBDeviceDescriptor.
    :param address: Interface number, defaults to 1.
    :return: URL string for PyFTDI connection.
    """
    return f"ftdi://::{serial_number}/{address}"


class Backend(Enum):
    """Backend enumeration for DK6 driver communication interfaces.

    This enumeration defines the available backend drivers that can be used
    for communication with DK6 devices, including FTDI-based drivers and
    serial communication options.
    """

    PYFTDI = 1
    PYLIBFTDI = 2
    FTD2xx = 3
    PYSERIAL = 4


class DeviceInfo:
    """Device information container for DK6 connected devices.

    This class encapsulates essential information about a connected device including
    USB identifiers, serial number, description, address, and backend interface.
    It provides a structured way to store and access device metadata for DK6
    operations and device management.
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
        """Initialize device information object.

        Creates a new device information instance with USB connection details,
        serial number, and backend configuration for SPSDK communication.

        :param device_id: Unique identifier for the device, either string or integer format.
        :param vid: USB Vendor ID for device identification.
        :param pid: USB Product ID for device identification.
        :param sn: Serial number string for unique device identification.
        :param description: Human-readable description of the device.
        :param address: Physical or logical address of the device.
        :param backend: Communication backend instance for device operations.
        """
        self.device_id = device_id
        self.vid = vid
        self.pid = pid
        self.sn = sn
        self.description = description
        self.address = address
        self.backend = backend

    def __str__(self) -> str:
        """Get string representation of the device information.

        Provides a formatted string containing all device identification and connection details
        including device ID, VID, PID, serial number, description, address, and backend type.

        :return: Formatted string with complete device information.
        """
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
    """FTDI driver interface for DK6 communication.

    This class provides a unified interface to multiple FTDI backend libraries
    (pyftdi, pylibftdi, and ftd2xx) enabling communication with DK6 devices
    through different driver implementations.
    """

    def __init__(self, backend: Backend) -> None:
        """Initialize driver interface and serial interface based on backend.

        Sets up the appropriate FTDI driver backend (PYFTDI, PYLIBFTDI, or FTD2xx) for DK6
        communication. Initializes driver and device objects based on the selected backend.

        :param backend: Backend type to use for FTDI communication.
        :raises SPSDKError: When required backend package is not installed or underlying
            library is missing.
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
        """Send a sequence that goes to ISP mode using FTDI bitbang device.

        The method sends a predefined sequence of bitbang commands to put the target device into
        In-System Programming (ISP) mode. It supports both PyFTDI and FTD2xx backends for FTDI
        device communication.

        :param device_id: Device identifier for the FTDI device to use for ISP sequence.
        :raises AssertionError: If driver is not properly initialized for PyFTDI backend.
        :raises ImportError: If required FTDI library is not available.
        """
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
        """List connected DK6 devices for the selected backend.

        Enumerates and returns information about all DK6 devices that are currently connected
        and accessible through the configured backend (PYFTDI, FTD2xx, or PYSERIAL).

        :return: List of DeviceInfo objects containing device details such as ID, VID, PID,
                 serial number, description, and address for each connected device.
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

        Configures and establishes connection to a serial device using the specified backend.
        The method supports multiple backends including PYFTDI, PYLIBFTDI, FTD2xx, and PYSERIAL.

        :param device_id: Device identifier (format depends on backend type)
        :param baudrate: UART baudrate for communication, defaults to 115200
        :param timeout: Read and write timeout in milliseconds, defaults to 5000 ms
        :raises SPSDKError: If invalid device_id is provided or device initialization fails
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
        """Get serial device.

        Retrieves the initialized serial device instance used for communication.

        :raises SPSDKError: If serial device is not initialized.
        :return: Serial device based on backend.
        """
        if not self.initialized or not self.dev:
            raise SPSDKError("Serial device is not initialized")
        return self.dev

    def set_baud_rate(self, baudrate: int) -> None:
        """Set baud rate for the UART communication.

        The method configures the baud rate for different backend implementations including
        PYFTDI, PYLIBFTDI, FTD2xx, and PYSERIAL. If the device is not initialized, the
        operation is skipped with an error log.

        :param baudrate: UART baud rate value to be set.
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
