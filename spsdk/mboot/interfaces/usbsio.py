#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright (c) 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for USB-SIO communication with a target device using MBoot protocol."""

import logging
from typing import Any, List, Optional, Union

import libusbsio
from libusbsio.libusbsio import LIBUSBSIO

from spsdk import SPSDKError
from spsdk.mboot.commands import CmdPacket, CmdResponse
from spsdk.mboot.exceptions import McuBootConnectionError, McuBootDataAbortError

from .base import Interface
from .uart import Uart

logger = logging.getLogger(__name__)


def scan_usbsio(config: str = None) -> List[Interface]:
    """Scan connected USB-SIO bridge devices.

    :param config: configuration string identifying spi or i2c SIO interface
    :return: list of matching RawHid devices
    :raises SPSDKError: When libusbsio library error or if no bridge device found
    """
    cfg = config.split(",") if config else []
    if len(cfg) <= 0 or not cfg[0] in ["spi", "i2c"]:
        raise SPSDKError("lpcusbsio connection needs 'spi' or 'i2c' configuration")

    sio = None

    try:
        # get the global singleton instance of LIBUSBSIO library
        sio = libusbsio.usbsio(loglevel=logger.level)

        # it may already be open (?)
        if not sio.IsOpen():
            if sio.GetNumPorts() < 1:
                raise Exception("No libusbsio bridge device found")
            # TODO: add support for multiple bridge devices, this would require to extend
            # command line configuration string by VID/PID and SIO port index. This would
            # break the legacy blhost command line compatibility.
            # For now, just open the first bridge device available
            if not sio.Open(0):
                raise Exception("Cannot open libusbsio device")
            logger.debug(f"USBSIO device open: {sio.GetVersion()}")
    except libusbsio.LIBUSBSIO_Exception as e:
        raise SPSDKError(f"Error in libusbsio interface: {e}")
    except Exception as e:
        raise SPSDKError(str(e))

    device: Optional[UsbSio] = None

    if cfg[0] == "i2c":
        if sio.GetNumI2CPorts() > 0:
            device = UsbSioI2C(config=config)
    elif cfg[0] == "spi":
        if sio.GetNumSPIPorts() > 0:
            device = UsbSioSPI(config=config)

    if not device:
        raise SPSDKError(f"No {cfg[0]} interface available in libusbsio device")
    return [device]


class UsbSio(Uart):
    """USBSIO general interface, base class for SPI or I2C communication over LIBUSBSIO.

    This class inherits from Uart communication as the SPI/I2C protocol is the same.
    The Uart's read and write methods are leveraged. The low-level _read and _write
    methods are overridden.
    """

    @property
    def is_opened(self) -> bool:
        """Indicates whether interface is open."""
        return True if self.port else False

    def __init__(self, config: str = None) -> None:
        """Initialize the Interface object."""
        # device is the LIBUSBSIO.PORT instance (LIBUSBSIO.SPI or LIBUSBSIO.I2C class)
        self.port: Optional[LIBUSBSIO.PORT] = None

        super().__init__()

        # work with the global LIBUSBSIO instance
        self.sio = libusbsio.usbsio()
        if not self.sio.IsOpen():
            raise SPSDKError("The libusbsio device is not open")

        # store USBSIO configuration and version
        self.config = config
        self.version = self.sio.GetVersion()

    def info(self) -> str:
        """Return string containing information about the interface."""
        return f"libusbsio interface '{self.config}'"


class UsbSioSPI(UsbSio):
    """USBSIO SPI interface."""

    def __init__(
        self,
        config: str = None,
        port: int = 0,
        ssel_port: int = 0,
        ssel_pin: int = 15,
        speed_khz: int = 1000,
        cpol: int = 1,
        cpha: int = 1,
    ) -> None:
        """Initialize the UsbSioSPI Interface object.

        :param config: configuration string passed from command line
        :param port: default SPI port to be used, typically 0 as only one port is supported by LPCLink2/MCULink
        :param ssel_port: bridge GPIO port used to drive SPI SSEL signal
        :param ssel_pin: bridge GPIO pin used to drive SPI SSEL signal
        :param speed_khz: SPI clock speed in kHz
        :param cpol: SPI clock polarity mode
        :param cpha: SPI clock phase mode
        :raises SPSDKError: When port configuration cannot be parsed
        """
        super().__init__(config=config)

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
            cfg = config.split(",")
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
                )

    def open(self) -> None:
        """Open the interface."""
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
        self, config: str = None, port: int = 0, address: int = 0x10, speed_khz: int = 100
    ) -> None:
        """Initialize the UsbSioI2C Interface object.

        :param config: configuration string passed from command line
        :param port: default I2C port to be used, typically 0 as only one port is supported by LPCLink2/MCULink
        :param address: I2C target device address
        :param speed_khz: I2C clock speed in kHz
        :raises SPSDKError: When port configuration cannot be parsed
        """
        super().__init__(config=config)

        # default configuration taken from parameters (and their default values)
        self.i2c_port = port
        self.i2c_address = address
        self.i2c_speed_khz = speed_khz

        # values can be also overridden by a configuration string
        if config:
            # config format: i2c[,<address>,<speed>]
            cfg = config.split(",")
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
                )

    def open(self) -> None:
        """Open the interface."""
        self.port: LIBUSBSIO.I2C = self.sio.I2C_Open(
            clockRate=self.i2c_speed_khz * 1000, portNum=self.i2c_port
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio I2C interface.\n")

    def close(self) -> None:
        """Close the interface."""
        if self.port:
            self.port.Close()
            self.port = None

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
