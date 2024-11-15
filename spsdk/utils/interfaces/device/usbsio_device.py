#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Low level usbsio device."""
import logging
import re
from dataclasses import dataclass
from typing import Optional, Union

import libusbsio
from libusbsio.libusbsio import LIBUSBSIO
from typing_extensions import Self

from spsdk.exceptions import SPSDKConnectionError, SPSDKError, SPSDKValueError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.interfaces.device.base import DeviceBase
from spsdk.utils.misc import Timeout, value_to_int
from spsdk.utils.usbfilter import USBDeviceFilter

logger = logging.getLogger(__name__)


@dataclass
class UsbSioConfig:
    """UsbSio configuration."""

    usb_config: Optional[str]
    port_num: int
    interface_args: list
    interface_kwargs: dict

    @classmethod
    def from_config_string(cls, config: str, interface: str) -> Self:
        """Parse the configuration string to UsbSioConfig object."""
        i = config.rfind(interface)
        if i < 0:
            raise SPSDKValueError(f"The configuration string must contain'{interface}'")
        # parse usb config(if exists)
        usb_config = config[:i] or None
        if usb_config:
            if usb_config.startswith("usb"):
                usb_config = usb_config.replace("usb", "", 1)
            usb_config = usb_config.strip(",")
        args, kwargs = cls._split_interface_config(config[i:])
        # first argument is always interface identifier with optional port number
        interface_identifier = args.pop(0)
        port_num_match = re.match(rf"^{interface}(?P<index>\d*)", interface_identifier)
        if not port_num_match:
            raise SPSDKValueError(
                f"The configuration string should be in format '{interface}<port_number>'."
                f"Got '{interface_identifier}'."
            )
        port_num = value_to_int(port_num_match.group("index"), 0)
        return cls(
            usb_config=usb_config,
            port_num=port_num,
            interface_args=args,
            interface_kwargs=kwargs,
        )

    @staticmethod
    def _split_interface_config(interface_config: str) -> tuple[list, dict]:
        """Convert the string configuration to the arguments and keyword arguments."""

        def _cast_arg(arg: str) -> Union[str, int]:
            """Cast the string argument to the type expected in object initialization."""
            try:
                return value_to_int(arg)
            except SPSDKError:
                return arg

        args = []
        kwargs = {}
        cfg = interface_config.split(",")
        for param in cfg:
            # a keyword argument
            if "=" in param:
                kwarg_parts = param.split("=")
                if len(kwarg_parts) != 2:
                    raise SPSDKValueError(f"Keyword argument: {param} must have format 'key=value'")
                kwargs[kwarg_parts[0].lower()] = _cast_arg(kwarg_parts[1])
            else:
                if kwargs:
                    raise SPSDKError("All arguments must be before keyword arguments.")
                args.append(_cast_arg(param))
        return (args, kwargs)


class UsbSioDevice(DeviceBase):
    """USBSIO device class."""

    INTERFACE = ""  # to be defined by the child class

    def __init__(
        self,
        dev: int = 0,
        port_num: int = 0,
        nirq_port: Optional[int] = None,
        nirq_pin: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the Interface object.

        :param dev: device index to be used, default is set to 0
        :param config: configuration string identifying spi or i2c SIO interface
        :param timeout: read timeout in milliseconds, defaults to 5000
        :raises SPSDKError: When LIBUSBSIO device is not opened.
        """
        # device is the LIBUSBSIO.PORT instance (LIBUSBSIO.SPI or LIBUSBSIO.I2C class)
        self.port: Optional[Union[LIBUSBSIO.SPI, LIBUSBSIO.I2C]] = None

        # work with the global LIBUSBSIO instance
        self.dev_ix = dev
        self.port_num = port_num
        self.sio = self._get_usbsio()
        self._timeout = timeout or 5000
        self.nirq_port = nirq_port
        self.nirq_pin = nirq_pin
        if self.is_nirq_enabled:
            self._config_nirq_pin()

    def _config_nirq_pin(self) -> None:
        if not (self.nirq_port and self.nirq_pin):
            raise SPSDKValueError("nIRQ port and pin must be defined.")
        self.sio.GPIO_ConfigIOPin(self.nirq_port, self.nirq_pin, 0x100)
        self.sio.GPIO_SetPortInDir(self.nirq_port, 1 << (self.nirq_pin - 1))
        if self.sio.GPIO_GetPin(self.nirq_port, self.nirq_pin) == 0:
            logger.warning(
                "The logical low has been detected on nIRQ pin."
                "Please check if nIRQ is enabled with command 'blhost -l <interface_config> get-property 28'"
            )

    def open(self) -> None:
        """Open the interface."""
        if self.sio is None:
            self.sio = self._get_usbsio()
        if not self.sio.IsDllLoaded():
            self.sio.LoadDLL()

        if not self.sio.IsOpen():
            detected_dev = self.sio.GetNumPorts()
            if detected_dev <= 0:
                raise SPSDKConnectionError(
                    "Cannot open LIBUSBSIO device because there is no one connected in system."
                )
            if detected_dev <= self.dev_ix:
                raise SPSDKConnectionError(
                    f"Cannot open LIBUSBSIO device-{self.dev_ix}, because the index is out of connected devices."
                )

            self.sio.Open(self.dev_ix)

    @property
    def timeout(self) -> int:
        """Timeout property."""
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Timeout property setter."""
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False otherwise.
        """
        return bool(self.port)

    def close(self) -> None:
        """Close the interface."""
        if self.port:
            self.port.Close()
            self.port = None
            if not self.sio.IsAnyPortOpen():
                self.sio.Close()

    @classmethod
    def scan(cls, config: str, timeout: Optional[int] = None) -> list[Self]:
        """Scan connected USB-SIO bridge devices.

        :param config: Configuration string identifying spi or i2c SIO interface
                        and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of matching UsbSio devices
        :raises SPSDKError: When libusbsio library error or if no bridge device found
        :raises SPSDKValueError: Invalid configuration detected.
        """
        if not cls.INTERFACE:
            raise SPSDKError("The 'INTERFACE' class attribute must be set in a subclass.")
        devices: list[Self] = []
        sio = cls._get_usbsio()
        usbsio_config = UsbSioConfig.from_config_string(config, cls.INTERFACE)
        usbsio_config.interface_kwargs["timeout"] = timeout or 5000

        usbsio_ports = cls.get_usbsio_devices(usbsio_config.usb_config)
        for usbsio_port in usbsio_ports:
            if not sio.Open(usbsio_port):
                raise SPSDKError(f"Cannot open libusbsio bridge {usbsio_port}.")
            available_port = {"i2c": sio.GetNumI2CPorts, "spi": sio.GetNumSPIPorts}[cls.INTERFACE]()
            if usbsio_config.port_num not in list(range(available_port)):
                logger.warning(
                    f"Given port {usbsio_config.port_num} is not amongst available ports: "
                    f"{','.join(list(str(n) for n in range(available_port)))}"
                )
                sio.Close()
                continue
            try:
                devices.append(
                    cls(
                        usbsio_port,
                        usbsio_config.port_num,
                        *usbsio_config.interface_args,
                        **usbsio_config.interface_kwargs,
                    )
                )
            except TypeError as e:
                raise SPSDKValueError(
                    f"Could not instantiate '{cls.INTERFACE}' device from given configuration: {e}"
                ) from e
            sio.Close()
        return devices

    def __str__(self) -> str:
        """Return string containing information about the interface."""
        class_name = self.__class__.__name__
        return f"libusbsio interface ({class_name})"

    def wait_for_nirq_state(self, state: int) -> None:
        """Wait until the nIRQ GPIO pin gets into desired state.

        :param state: Expected state
        """
        if state not in [0, 1]:
            raise SPSDKValueError("State must be either 0 or 1.")
        if not self.is_nirq_enabled:
            raise SPSDKError("The nIRQ functionality is disabled. nIRQ pin must be defined.")
        if not (self.nirq_port and self.nirq_pin):
            raise SPSDKValueError("nIRQ port and pin must be defined.")
        timeout = Timeout(self.timeout, "ms")
        while not timeout.overflow():
            nirq_state = self.sio.GPIO_GetPin(self.nirq_port, self.nirq_pin)
            if nirq_state == state:
                return
        raise SPSDKError(
            "The nIRQ pin has not been triggered on time. Try to increase the timeout."
        )

    @property
    def is_nirq_enabled(self) -> bool:
        """Is nIRQ functionality enabled."""
        return self.nirq_pin is not None and self.nirq_port is not None

    @staticmethod
    def _process_interface_config(
        interface_config: str, timeout: Optional[int] = None
    ) -> tuple[list, dict]:
        """Convert the string configuration to the arguments and keyword arguments."""

        def _cast_arg(arg: str) -> Union[str, int]:
            """Cast the string argument to the type expected in object initialization."""
            try:
                return value_to_int(arg)
            except SPSDKError:
                return arg

        args = []
        kwargs = {}
        cfg = interface_config.split(",")
        for param in cfg:
            # a keyword argument
            if "=" in param:
                kwarg_parts = param.split("=")
                if len(kwarg_parts) != 2:
                    raise SPSDKValueError(f"Keyword argument: {param} must have format 'key=value'")
                kwargs[kwarg_parts[0].lower()] = _cast_arg(kwarg_parts[1])
            else:
                if kwargs:
                    raise SPSDKError("All arguments must be before keyword arguments.")
                args.append(_cast_arg(param))
        if timeout is not None:
            kwargs["timeout"] = timeout
        return (args, kwargs)

    @staticmethod
    def _get_usbsio() -> LIBUSBSIO:
        """Wraps getting USBSIO library to raise SPSDK errors in case of problem.

        :return: LIBUSBSIO object
        :raises SPSDKError: When libusbsio library error or if no bridge device found
        """
        try:
            # get the global singleton instance of LIBUSBSIO library
            libusbsio_logger = logging.getLogger("libusbsio")
            return libusbsio.usbsio(loglevel=libusbsio_logger.getEffectiveLevel())
        except libusbsio.LIBUSBSIO_Exception as e:
            raise SPSDKError(f"Error in libusbsio interface: {e}") from e
        except Exception as e:
            raise SPSDKError(str(e)) from e

    @classmethod
    def get_usbsio_devices(cls, usb_config: Optional[str] = None) -> list[int]:
        """Returns list of ports indexes of USBSIO devices.

        It could be filtered by standard SPSDK USB filters.

        :param usb_config: Could contain USB filter configuration, defaults to None
        :return: List of port indexes of founded USBSIO device
        """

        def _filter_usb(sio: LIBUSBSIO, ports: list[int], flt: str) -> list[int]:
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
                    raise SPSDKError(f"Cannot retrieve information from LIBUSBSIO device {port}.")
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

        port_indexes = []

        sio = UsbSioDevice._get_usbsio()
        # it may already be open (?), in that case, just close it - We are scan function!
        if sio.IsOpen():
            sio.Close()

        port_indexes.extend(list(range(sio.GetNumPorts())))

        # filter out the USB devices
        if usb_config:
            port_indexes = _filter_usb(sio, port_indexes, usb_config)

        return port_indexes


class UsbSioSPIDevice(UsbSioDevice):
    """USBSIO SPI interface."""

    INTERFACE = "spi"

    def __init__(
        self,
        dev: int = 0,
        port_num: int = 0,
        ssel_port: int = 0,
        ssel_pin: int = 15,
        speed_khz: int = 1000,
        cpol: int = 1,
        cpha: int = 1,
        nirq_port: Optional[int] = None,
        nirq_pin: Optional[int] = None,
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
        super().__init__(
            dev=dev, port_num=port_num, nirq_port=nirq_port, nirq_pin=nirq_pin, timeout=timeout
        )
        self.spi_sselport = ssel_port
        self.spi_sselpin = ssel_pin
        self.spi_speed_khz = speed_khz
        self.spi_cpol = cpol
        self.spi_cpha = cpha

    def open(self) -> None:
        """Open the interface."""
        super().open()

        self.port: LIBUSBSIO.SPI = self.sio.SPI_Open(
            portNum=self.port_num,
            busSpeed=self.spi_speed_khz * 1000,
            cpol=self.spi_cpol,
            cpha=self.spi_cpha,
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio SPI interface.\n")

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKConnectionError: When reading data from device fails
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
            raise SPSDKConnectionError(str(e)) from e
        if result < 0 or not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKConnectionError: When sending the data fails
        :raises SPSDKTimeoutError: When data could not be written
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            (dummy, result) = self.port.Transfer(
                devSelectPort=self.spi_sselport, devSelectPin=self.spi_sselpin, txData=data
            )
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0:
            raise SPSDKTimeoutError()


class UsbSioI2CDevice(UsbSioDevice):
    """USBSIO I2C interface."""

    INTERFACE = "i2c"

    def __init__(
        self,
        dev: int = 0,
        port_num: int = 0,
        address: int = 0x10,
        speed_khz: int = 100,
        nirq_port: Optional[int] = None,
        nirq_pin: Optional[int] = None,
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
        super().__init__(
            dev=dev, port_num=port_num, nirq_port=nirq_port, nirq_pin=nirq_pin, timeout=timeout
        )
        self.i2c_address = address
        self.i2c_speed_khz = speed_khz

    def open(self) -> None:
        """Open the interface."""
        super().open()

        self.port: LIBUSBSIO.I2C = self.sio.I2C_Open(
            clockRate=self.i2c_speed_khz * 1000, portNum=self.port_num
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio I2C interface.\n")

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read 'length' amount for bytes from device.

        :param length: Number of bytes to read
        :param timeout: Read timeout
        :return: Data read from the device
        :raises SPSDKConnectionError: When reading data from device fails
        :raises SPSDKTimeoutError: When no data received
        """
        try:
            (data, result) = self.port.DeviceRead(devAddr=self.i2c_address, rxSize=length)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0 or not data:
            raise SPSDKTimeoutError()
        logger.debug(f"<{' '.join(f'{b:02x}' for b in data)}>")
        return data

    def write(self, data: bytes, timeout: Optional[int] = None) -> None:
        """Send data to device.

        :param data: Data to send
        :param timeout: Write timeout
        :raises SPSDKConnectionError: When sending the data fails
        :raises TimeoutError: When data NAKed or could not be written
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            result = self.port.DeviceWrite(devAddr=self.i2c_address, txData=data)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0:
            raise SPSDKTimeoutError()
