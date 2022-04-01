#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2019-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for USB-SIO communication with a target device using MBoot protocol."""

import logging
from typing import List, Optional

import libusbsio
from libusbsio.libusbsio import LIBUSBSIO

from spsdk import SPSDKError, SPSDKValueError
from spsdk.mboot.exceptions import McuBootConnectionError
from spsdk.utils.usbfilter import USBDeviceFilter

from .base import MBootInterface
from .uart import Uart

logger = logging.getLogger(__name__)


def _get_usbsio() -> LIBUSBSIO:
    """Wraps getting USBSIO library to raise SPSDK errors in case of problem.

    :return: LIBUSBSIO object
    :raises SPSDKError: When libusbsio library error or if no bridge device found
    """
    try:
        # get the global singleton instance of LIBUSBSIO library
        return libusbsio.usbsio(loglevel=logger.level)
    except libusbsio.LIBUSBSIO_Exception as e:
        raise SPSDKError(f"Error in libusbsio interface: {e}") from e
    except Exception as e:
        raise SPSDKError(str(e)) from e


def get_usbsio_devices(config: str = None) -> List[int]:
    """Returns list of ports indexes of USBSIO devices.

    It could be filtered by standard SPSDK USB filters.

    :param config: Could contain USB filter configuration, defaults to None
    :return: List of port indexes of founded USBSIO device
    """

    def _filter_usb(sio: LIBUSBSIO, ports: List[int], flt: str) -> List[int]:
        """Filter the  LIBUSBSIO device.

        :param sio: LIBUSBSIO instance.
        :param ports: Input list of LIBUSBSIO available ports.
        :param flt: Filter string (PATH, PID/VID, SERIAL_NUMBER)
        :raises SPSDKError: When libusbsio library error or if no bridge device found
        :return: List with selected device, empty list otherwise.
        """
        usb_filter = USBDeviceFilter(flt.casefold())
        port_indexes = []
        for port in ports:
            info = sio.GetDeviceInfo(port)
            if not info:
                raise SPSDKError(f"Cannot retrive information from LIBUSBSIO device {port}.")
            dev_info = {
                "vendor_id": info.vendor_id,
                "product_id": info.product_id,
                "serial_number": info.serial_number,
                "path": info.path,
            }
            if usb_filter.compare(dev_info):
                port_indexes.append(port)
                break
        return port_indexes

    cfg = config.split(",") if config else []
    port_indexes = []

    sio = _get_usbsio()
    # it may already be open (?), in that case, just close it - We are scan function!
    if sio.IsOpen():
        sio.Close()

    port_indexes.extend(list(range(sio.GetNumPorts())))

    # filter out the USB devices
    if cfg and cfg[0] == "usb":
        port_indexes = _filter_usb(sio, port_indexes, cfg[1])

    return port_indexes


def scan_usbsio(config: str = None, timeout: int = 5000) -> List["UsbSio"]:
    """Scan connected USB-SIO bridge devices.

    :param config: Configuration string identifying spi or i2c SIO interface
                    and could filter out USB devices
    :param timeout: Read timeout in milliseconds, defaults to 5000
    :return: List of matching UsbSio devices
    :raises SPSDKError: When libusbsio library error or if no bridge device found
    :raises SPSDKValueError: Invalid configuration detected.
    """
    cfg = config.split(",") if config else []
    if all(intf in cfg for intf in ["i2c", "spi"]):
        raise SPSDKValueError(f"Cannot be specified spi and i2c together in configuration: {cfg}")
    intf_specified = any(intf in cfg for intf in ["i2c", "spi"])

    port_indexes = get_usbsio_devices(config)
    sio = _get_usbsio()
    devices: List["UsbSio"] = []
    for port in port_indexes:
        if not sio.Open(port):
            raise SPSDKError(f"Cannot open libusbsio bridge {port}.")
        i2c_ports = sio.GetNumI2CPorts()
        if i2c_ports:
            if "i2c" in cfg:
                devices.append(UsbSioI2C(dev=port, config=config, timeout=timeout))
            elif not intf_specified:
                devices.extend(
                    [UsbSioI2C(dev=port, port=p, timeout=timeout) for p in range(i2c_ports)]
                )
        spi_ports = sio.GetNumSPIPorts()
        if spi_ports:
            if "spi" in cfg:
                devices.append(UsbSioSPI(dev=port, config=config, timeout=timeout))
            elif not intf_specified:
                devices.extend(
                    [UsbSioSPI(dev=port, port=p, timeout=timeout) for p in range(spi_ports)]
                )
        if sio.Close() < 0:
            raise SPSDKError(f"Cannot close libusbsio bridge {port}.")
        # re-init the libusb to prepare it for next open
        sio.GetNumPorts()
    return devices


def scan_usbsio_i2c(config: str = None, timeout: int = 5000) -> List["UsbSioI2C"]:
    """Scan connected USB-SIO bridge devices and return just I2C devices.

    :param config: Configuration string identifying spi or i2c SIO interface
                    and could filter out USB devices.
    :param timeout: Read timeout in milliseconds, defaults to 5000
    :return: List of matching UsbSioI2C devices only
    """
    devices = scan_usbsio(config, timeout)
    return [x for x in devices if isinstance(x, UsbSioI2C)]


def scan_usbsio_spi(config: str = None, timeout: int = 5000) -> List["UsbSioSPI"]:
    """Scan connected USB-SIO bridge devices and return just SPI devices.

    :param config: Configuration string identifying spi or i2c SIO interface
                    and could filter out USB devices.
    :param timeout: Read timeout in milliseconds, defaults to 5000
    :return: List of matching UsbSioSPI devices only
    """
    devices = scan_usbsio(config, timeout)
    return [x for x in devices if isinstance(x, UsbSioSPI)]


class UsbSio(Uart):
    """USBSIO general interface, base class for SPI or I2C communication over LIBUSBSIO.

    This class inherits from Uart communication as the SPI/I2C protocol is the same.
    The Uart's read and write methods are leveraged. The low-level _read and _write
    methods are overridden.
    """

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return bool(self.port)

    def __init__(self, dev: int = 0, config: str = None, timeout: int = 5000) -> None:
        """Initialize the Interface object.

        :param dev: device index to be used, default is set to 0
        :param config: configuration string identifying spi or i2c SIO interface
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When LIBUSBSIO device is not opened.
        """
        # device is the LIBUSBSIO.PORT instance (LIBUSBSIO.SPI or LIBUSBSIO.I2C class)
        self.port: Optional[LIBUSBSIO.PORT] = None

        # work with the global LIBUSBSIO instance
        self.dev_ix = dev
        self.sio = _get_usbsio()

        super().__init__(timeout=timeout)

        # store USBSIO configuration and version
        self.config = config

    def info(self) -> str:
        """Return string containing information about the interface."""
        return f"libusbsio interface '{self.config}'"

    @staticmethod
    def get_interface_cfg(config: str, interface: str) -> str:
        """Return part of interface config.

        :param config: Full config of LIBUSBSIO
        :param interface: Name of interface to find.
        :return: Part with interface config.
        """
        i = config.rfind(interface)
        if i < 0:
            return ""
        return config[i]


class UsbSioSPI(UsbSio):
    """USBSIO SPI interface."""

    FRAME_START_BYTE_NOT_READY = 0xFF

    def __init__(
        self,
        config: str = None,
        dev: int = 0,
        port: int = 0,
        ssel_port: int = 0,
        ssel_pin: int = 15,
        speed_khz: int = 1000,
        cpol: int = 1,
        cpha: int = 1,
        timeout: int = 5000,
    ) -> None:
        """Initialize the UsbSioSPI Interface object.

        :param config: configuration string passed from command line
        :param dev: device index to be used, default is set to 0
        :param port: default SPI port to be used, typically 0 as only one port is supported by LPCLink2/MCULink
        :param ssel_port: bridge GPIO port used to drive SPI SSEL signal
        :param ssel_pin: bridge GPIO pin used to drive SPI SSEL signal
        :param speed_khz: SPI clock speed in kHz
        :param cpol: SPI clock polarity mode
        :param cpha: SPI clock phase mode
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When port configuration cannot be parsed
        """
        super().__init__(dev=dev, config=config, timeout=timeout)

        # default configuration taken from parameters (and their default values)
        self.spi_port = port
        self.spi_sselport = ssel_port
        self.spi_sselpin = ssel_pin
        self.spi_speed_khz = speed_khz
        self.spi_cpol = cpol
        self.spi_cpha = cpha

        # values can be also overridden by a configuration string
        if config:
            # config format: spi[,<port>,<pin>,<speed>,<cpol>,<cpha>]
            cfg = self.get_interface_cfg(config, "spi").split(",")
            try:
                self.spi_sselport = int(cfg[1], 0)
                self.spi_sselpin = int(cfg[2], 0)
                self.spi_speed_khz = int(cfg[3], 0)
                self.spi_cpol = int(cfg[4], 0)
                self.spi_cpha = int(cfg[5], 0)
            except IndexError:
                pass
            except Exception as e:
                raise SPSDKError(
                    "Cannot parse lpcusbsio SPI parameters.\n"
                    "Expected: spi[,<port>,<pin>,<speed_kHz>,<cpol>,<cpha>]\n"
                    f"Given:    {config}"
                ) from e

    def open(self) -> None:
        """Open the interface."""
        if not self.sio.IsOpen():
            self.sio.Open(self.dev_ix)

        self.port: LIBUSBSIO.SPI = self.sio.SPI_Open(
            portNum=self.spi_port,
            busSpeed=self.spi_speed_khz * 1000,
            cpol=self.spi_cpol,
            cpha=self.spi_cpha,
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio SPI interface.\n")

    def close(self) -> None:
        """Close the interface."""
        if self.port:
            self.port.Close()
            self.port = None
            # if not self.sio.IsAnyPortOpen(): #TODO temporary hack till new version of libusbsio greater than 2.1.11
            self.sio.Close()

    def _read(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises McuBootConnectionError: When reading data from device fails
        :raises TimeoutError: When no data received
        """
        try:
            (data, result) = self.port.Transfer(
                devSelectPort=self.spi_sselport,
                devSelectPin=self.spi_sselpin,
                txData=None,
                size=length,
            )
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e
        if result < 0 or not data:
            raise TimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send
        :raises McuBootConnectionError: When sending the data fails
        :raises TimeoutError: When data could not be written
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            (dummy, result) = self.port.Transfer(
                devSelectPort=self.spi_sselport, devSelectPin=self.spi_sselpin, txData=data
            )
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e
        if result < 0:
            raise TimeoutError()


class UsbSioI2C(UsbSio):
    """USBSIO I2C interface."""

    def __init__(
        self,
        config: str = None,
        dev: int = 0,
        port: int = 0,
        address: int = 0x10,
        speed_khz: int = 100,
        timeout: int = 5000,
    ) -> None:
        """Initialize the UsbSioI2C Interface object.

        :param config: configuration string passed from command line
        :param dev: device index to be used, default is set to 0
        :param port: default I2C port to be used, typically 0 as only one port is supported by LPCLink2/MCULink
        :param address: I2C target device address
        :param speed_khz: I2C clock speed in kHz
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When port configuration cannot be parsed
        """
        super().__init__(dev=dev, config=config, timeout=timeout)

        # default configuration taken from parameters (and their default values)
        self.i2c_port = port
        self.i2c_address = address
        self.i2c_speed_khz = speed_khz

        # values can be also overridden by a configuration string
        if config:
            # config format: i2c[,<address>,<speed>]
            cfg = self.get_interface_cfg(config, "i2c").split(",")
            try:
                self.i2c_address = int(cfg[1], 0)
                self.i2c_speed_khz = int(cfg[2], 0)
            except IndexError:
                pass
            except Exception as e:
                raise SPSDKError(
                    "Cannot parse lpcusbsio I2C parameters.\n"
                    "Expected: i2c[,<address>,<speed_kHz>]\n"
                    f"Given:    {config}"
                ) from e

    def open(self) -> None:
        """Open the interface."""
        if not self.sio.IsOpen():
            self.sio.Open(self.dev_ix)

        self.port: LIBUSBSIO.I2C = self.sio.I2C_Open(
            clockRate=self.i2c_speed_khz * 1000, portNum=self.i2c_port
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio I2C interface.\n")

    def close(self) -> None:
        """Close the interface."""
        if self.port:
            # Preventive Reset of I2C device to be ready to reopen in case of any pending problem
            self.port.Reset()
            self.port.Close()
            self.port = None
            # if not self.sio.IsAnyPortOpen(): #TODO temporary hack till new version of libusbsio greater than 2.1.11
            self.sio.Close()

    def _read(self, length: int) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :return: Data read from the device
        :raises TimeoutError: Time-out
        :raises McuBootConnectionError: When reading data from device fails
        :raises TimeoutError: When no data received
        """
        try:
            (data, result) = self.port.DeviceRead(devAddr=self.i2c_address, rxSize=length)
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e
        if result < 0 or not data:
            raise TimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def _write(self, data: bytes) -> None:
        """Send data to device.

        :param data: Data to send
        :raises McuBootConnectionError: When sending the data fails
        :raises TimeoutError: When data NAKed or could not be written
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            result = self.port.DeviceWrite(devAddr=self.i2c_address, txData=data)
        except Exception as e:
            raise McuBootConnectionError(str(e)) from e
        if result < 0:
            raise TimeoutError()
