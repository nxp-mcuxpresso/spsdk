#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USB-SIO device interface implementation.

This module provides low-level interface classes for communicating with USB-SIO
devices, supporting both SPI and I2C protocols. It includes configuration
management and device abstraction for NXP USB-SIO hardware.
"""

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
    """UsbSio configuration data container.

    This class represents configuration parameters for USB-SIO device interfaces,
    including USB connection settings, port numbers, and interface-specific
    arguments. It provides parsing functionality to convert configuration strings
    into structured configuration objects.
    """

    usb_config: Optional[str]
    port_num: int
    interface_args: list
    interface_kwargs: dict

    @classmethod
    def from_config_string(cls, config: str, interface: str) -> Self:
        """Parse the configuration string to UsbSioConfig object.

        Extracts USB configuration and interface-specific parameters from a configuration string.
        The method parses the interface identifier, port number, and additional arguments.

        :param config: Configuration string containing USB and interface settings.
        :param interface: Interface type identifier to search for in the configuration.
        :raises SPSDKValueError: Invalid configuration string format or missing interface.
        :return: UsbSioConfig object with parsed configuration parameters.
        """
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
        """Parse string configuration into positional and keyword arguments.

        Converts a comma-separated configuration string into separate lists of positional
        arguments and keyword arguments. Arguments are automatically cast to integers
        when possible, otherwise kept as strings. All positional arguments must come
        before any keyword arguments.

        :param interface_config: Comma-separated configuration string with format
                                "arg1,arg2,key1=value1,key2=value2"
        :raises SPSDKValueError: Invalid keyword argument format (not 'key=value').
        :raises SPSDKError: Positional argument found after keyword arguments.
        :return: Tuple containing list of positional arguments and dictionary of
                 keyword arguments.
        """

        def _cast_arg(arg: str) -> Union[str, int]:
            """Cast the string argument to the type expected in object initialization.

            Attempts to convert a string argument to an integer using value_to_int().
            If conversion fails, returns the original string unchanged.

            :param arg: String argument to be cast to appropriate type.
            :return: Integer value if conversion succeeds, otherwise original string.
            """
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
    """USBSIO device interface for NXP MCU communication.

    This class provides a unified interface for communicating with NXP MCUs through
    USBSIO devices, supporting both SPI and I2C protocols. It manages device
    connections, GPIO configuration for interrupt handling, and provides methods
    for opening, closing, and scanning USBSIO devices.

    :cvar INTERFACE: Interface type identifier to be defined by child classes.
    """

    INTERFACE = ""  # to be defined by the child class

    def __init__(
        self,
        dev: int = 0,
        port_num: int = 0,
        nirq_port: Optional[int] = None,
        nirq_pin: Optional[int] = None,
        timeout: Optional[int] = None,
    ) -> None:
        """Initialize the USBSIO device interface.

        Sets up the USBSIO device connection with specified parameters including device index,
        port configuration, optional interrupt handling, and communication timeout.

        :param dev: Device index to be used, defaults to 0.
        :param port_num: Port number for the USBSIO interface.
        :param nirq_port: Optional interrupt port number for NIRQ functionality.
        :param nirq_pin: Optional interrupt pin number for NIRQ functionality.
        :param timeout: Read timeout in milliseconds, defaults to 5000.
        :raises SPSDKError: When LIBUSBSIO device cannot be opened or configured.
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
        """Configure nIRQ pin for interrupt handling.

        Sets up the nIRQ (Notification Interrupt) pin as an input GPIO pin and checks its
        initial state. The pin is used to detect interrupt conditions from connected devices.
        If the pin is detected as low during configuration, a warning is logged suggesting
        to verify nIRQ enablement.

        :raises SPSDKValueError: When nIRQ port or pin is not defined.
        """
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
        """Open the USB SIO interface for communication.

        Initializes the USB SIO device by loading the required DLL library and
        establishing connection to the specified device index. The method ensures
        the interface is ready for data transfer operations.

        :raises SPSDKConnectionError: When USB SIO device cannot be opened or DLL fails to load.
        """
        if self.sio is None:
            self.sio = self._get_usbsio()
        if not self.sio.IsDllLoaded():
            self.sio.LoadDLL()

        if not self.sio.IsOpen():
            self.sio.Open(self.dev_ix)

    @property
    def timeout(self) -> int:
        """Get timeout value for the device communication.

        :return: Timeout value in milliseconds.
        """
        return self._timeout

    @timeout.setter
    def timeout(self, value: int) -> None:
        """Set timeout value for the device communication.

        :param value: Timeout value in milliseconds.
        """
        self._timeout = value

    @property
    def is_opened(self) -> bool:
        """Indicates whether device is open.

        :return: True if device is open, False otherwise.
        """
        return bool(self.port)

    def close(self) -> None:
        """Close the USB SIO interface.

        Closes the current port connection and releases the SIO resources if no other
        ports are open. Sets the port reference to None after closing.
        """
        if self.port:
            self.port.Close()
            self.port = None
            if not self.sio.IsAnyPortOpen():
                self.sio.Close()

    @classmethod
    def scan(cls, config: str, timeout: Optional[int] = None) -> list[Self]:
        """Scan connected USB-SIO bridge devices.

        The method discovers and initializes USB-SIO bridge devices that match the specified
        configuration. It opens each available USB-SIO port, validates the requested interface
        port number, and creates device instances for successful matches.

        :param config: Configuration string identifying spi or i2c SIO interface and could
                       filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of matching UsbSio devices
        :raises SPSDKError: When libusbsio library error or if no bridge device found
        :raises SPSDKValueError: Invalid configuration detected
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
        """Return string representation of the USB SIO device interface.

        Provides a formatted string containing the class name and interface type
        for debugging and logging purposes.

        :return: String representation of the interface.
        """
        class_name = self.__class__.__name__
        return f"libusbsio interface ({class_name})"

    def wait_for_nirq_state(self, state: int) -> None:
        """Wait until the nIRQ GPIO pin reaches the desired state.

        This method polls the nIRQ GPIO pin until it matches the expected state or times out.
        The nIRQ functionality must be enabled and properly configured before calling this method.

        :param state: Expected GPIO pin state (0 for low, 1 for high).
        :raises SPSDKValueError: Invalid state value or nIRQ port/pin not defined.
        :raises SPSDKError: nIRQ functionality disabled or timeout occurred.
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
        """Check if nIRQ functionality is enabled.

        The method verifies that both nIRQ pin and port are properly configured
        and available for use.

        :return: True if nIRQ functionality is enabled, False otherwise.
        """
        return self.nirq_pin is not None and self.nirq_port is not None

    @staticmethod
    def _process_interface_config(
        interface_config: str, timeout: Optional[int] = None
    ) -> tuple[list, dict]:
        """Convert the string configuration to the arguments and keyword arguments.

        Parses a comma-separated configuration string into positional and keyword arguments
        for device interface initialization. Arguments must come before keyword arguments.

        :param interface_config: Comma-separated configuration string with args and key=value pairs.
        :param timeout: Optional timeout value to add to keyword arguments.
        :raises SPSDKValueError: Invalid keyword argument format.
        :raises SPSDKError: Arguments found after keyword arguments.
        :return: Tuple containing list of positional arguments and dictionary of keyword arguments.
        """

        def _cast_arg(arg: str) -> Union[str, int]:
            """Cast the string argument to the type expected in object initialization.

            Attempts to convert a string argument to an integer using value_to_int().
            If conversion fails, returns the original string unchanged.

            :param arg: String argument to be cast to appropriate type.
            :return: Integer value if conversion succeeds, otherwise original string.
            """
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
        """Get USBSIO library instance with SPSDK error handling.

        Wraps the libusbsio library initialization to provide consistent SPSDK error handling
        and logging configuration.

        :return: LIBUSBSIO object instance
        :raises SPSDKError: When libusbsio library error occurs or if no bridge device found
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
        """Get list of port indexes of USBSIO devices.

        The method retrieves all available USBSIO device ports and optionally filters them
        using standard SPSDK USB filters based on VID/PID, serial number, or device path.

        :param usb_config: USB filter configuration string for device filtering, defaults to None
        :raises SPSDKError: When libusbsio library error occurs or device information cannot be retrieved
        :return: List of port indexes of found USBSIO devices
        """

        def _filter_usb(sio: LIBUSBSIO, ports: list[int], flt: str) -> list[int]:
            """Filter LIBUSBSIO devices based on provided criteria.

            Filters the list of available LIBUSBSIO ports using the specified filter string which can
            match against device path, PID/VID, or serial number.

            :param sio: LIBUSBSIO instance used to retrieve device information.
            :param ports: List of available LIBUSBSIO port numbers to filter.
            :param flt: Filter string containing PATH, PID/VID, or SERIAL_NUMBER criteria.
            :raises SPSDKError: When libusbsio library error occurs or device information cannot be
                retrieved.
            :return: List of port indexes matching the filter criteria, empty list if no matches.
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
    """USBSIO SPI Device Interface.

    This class provides SPI communication capabilities through USB-SIO bridge devices
    such as LPCLink2 or MCULink. It manages SPI protocol configuration including
    clock settings, polarity, phase, and slave select control.

    :cvar INTERFACE: Interface type identifier for SPI protocol.
    """

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

        Configures SPI communication parameters including device selection, GPIO pins for chip select,
        clock settings, and timing parameters for USB-SIO bridge communication.

        :param dev: Device index to be used, defaults to 0
        :param port_num: SPI port number, typically 0 for LPCLink2/MCULink
        :param ssel_port: Bridge GPIO port used to drive SPI SSEL signal
        :param ssel_pin: Bridge GPIO pin used to drive SPI SSEL signal, defaults to 15
        :param speed_khz: SPI clock speed in kHz, defaults to 1000
        :param cpol: SPI clock polarity mode, defaults to 1
        :param cpha: SPI clock phase mode, defaults to 1
        :param nirq_port: Optional GPIO port for interrupt signal
        :param nirq_pin: Optional GPIO pin for interrupt signal
        :param timeout: Read timeout in milliseconds, defaults to 5000
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
        """Open the USBSIO SPI interface.

        Initializes and opens the SPI port using the configured parameters including port number,
        bus speed, clock polarity, and clock phase. The interface must be opened before any
        SPI communication can occur.

        :raises SPSDKError: When the USBSIO SPI interface cannot be opened.
        """
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
        """Read specified number of bytes from the SPI device.

        Performs a SPI transfer operation to read data from the connected device using the configured
        select port and pin settings.

        :param length: Number of bytes to read from the device.
        :param timeout: Read timeout in milliseconds (currently not used in implementation).
        :return: Data read from the device.
        :raises SPSDKConnectionError: When reading data from device fails.
        :raises SPSDKTimeoutError: When no data received or transfer result indicates failure.
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
        """Send data to device via USB-SIO interface.

        This method transfers data to the connected device using the SPI interface
        through the USB-SIO bridge. The data is sent synchronously and any transfer
        errors are converted to appropriate SPSDK exceptions.

        :param data: Binary data to send to the device.
        :param timeout: Write timeout in milliseconds (currently not used).
        :raises SPSDKConnectionError: When the data transfer fails due to communication issues.
        :raises SPSDKTimeoutError: When the transfer operation times out or returns error code.
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
    """USBSIO I2C Device Interface.

    This class provides I2C communication capabilities through USB-SIO devices
    such as LPCLink2 or MCULink. It manages I2C transactions including device
    addressing, clock speed configuration, and data transfer operations.

    :cvar INTERFACE: Interface type identifier for I2C protocol.
    """

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

        :param dev: Device index to be used, defaults to 0.
        :param port_num: I2C port number to be used, typically 0 as only one port is supported by LPCLink2/MCULink.
        :param address: I2C target device address, defaults to 0x10.
        :param speed_khz: I2C clock speed in kHz, defaults to 100.
        :param nirq_port: Optional NIRQ port number.
        :param nirq_pin: Optional NIRQ pin number.
        :param timeout: Read timeout in milliseconds, defaults to 5000.
        :raises SPSDKError: When port configuration cannot be parsed.
        """
        super().__init__(
            dev=dev, port_num=port_num, nirq_port=nirq_port, nirq_pin=nirq_pin, timeout=timeout
        )
        self.i2c_address = address
        self.i2c_speed_khz = speed_khz

    def open(self) -> None:
        """Open the USB-SIO I2C interface.

        Initializes the I2C port using the configured speed and port number settings.
        Calls the parent class open method and then opens the LIBUSBSIO I2C interface.

        :raises SPSDKError: When the lpcusbsio I2C interface cannot be opened.
        """
        super().open()

        self.port: LIBUSBSIO.I2C = self.sio.I2C_Open(
            clockRate=self.i2c_speed_khz * 1000, portNum=self.port_num
        )
        if not self.port:
            raise SPSDKError("Cannot open lpcusbsio I2C interface.\n")

    def read(self, length: int, timeout: Optional[int] = None) -> bytes:
        """Read data from the USB-SIO I2C device.

        The method reads the specified number of bytes from the connected I2C device
        through the USB-SIO interface. It handles communication errors and timeouts
        appropriately.

        :param length: Number of bytes to read from the device.
        :param timeout: Read timeout in milliseconds (currently not used by underlying API).
        :return: Data read from the device.
        :raises SPSDKConnectionError: When reading data from device fails.
        :raises SPSDKTimeoutError: When no data received or operation times out.
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

        :param data: Data to send to the device.
        :param timeout: Write timeout in milliseconds.
        :raises SPSDKConnectionError: When sending the data fails.
        :raises SPSDKTimeoutError: When data NAKed or could not be written.
        """
        logger.debug(f"[{' '.join(f'{b:02x}' for b in data)}]")
        try:
            result = self.port.DeviceWrite(devAddr=self.i2c_address, txData=data)
        except Exception as e:
            raise SPSDKConnectionError(str(e)) from e
        if result < 0:
            raise SPSDKTimeoutError()
