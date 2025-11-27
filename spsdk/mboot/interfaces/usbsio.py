#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK USBSIO interface implementation for MBoot protocol communication.

This module provides USBSIO-based communication interfaces for MBoot protocol,
supporting both I2C and SPI transport layers through USB-to-serial bridge devices.
"""

from typing import Optional, Union

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol, to_int
from spsdk.utils.interfaces.device.usbsio_device import UsbSioI2CDevice, UsbSioSPIDevice


class MbootUsbSioInterface(MbootSerialProtocol):
    """USBSIO interface for MBoot communication.

    This class provides MBoot protocol communication over USBSIO devices,
    supporting both I2C and SPI interfaces with enhanced interrupt-based
    data waiting capabilities.
    """

    device: Union[UsbSioI2CDevice, UsbSioSPIDevice]

    def _wait_for_data(self) -> int:
        """Wait for first "not ready" frame.

        This method waits for data availability by checking the NIRQ (Notification Interrupt) state
        if the device supports it, otherwise falls back to the parent implementation.

        :return: Integer value read from the device after NIRQ state change.
        """
        if not self.device.is_nirq_enabled:
            return super()._wait_for_data()
        self.device.wait_for_nirq_state(state=0)
        return to_int(self.device.read(1))


class MbootUsbSioI2CInterface(MbootUsbSioInterface):
    """MBOOT USB-SIO I2C communication interface.

    This class provides I2C communication capabilities for MBOOT protocol over USB-SIO
    bridge devices, enabling secure provisioning operations through I2C connections.

    :cvar identifier: Interface type identifier for USB-SIO I2C communication.
    """

    device: UsbSioI2CDevice
    identifier = "usbsio_i2c"

    def __init__(self, device: UsbSioI2CDevice):
        """Initialize the UsbSioI2C interface.

        :param device: The USB-SIO I2C device instance to be used for communication.
        """
        super().__init__(device=device)

    @classmethod
    def scan(cls, config: str, timeout: Optional[int] = None) -> list[Self]:
        """Scan connected USB-SIO bridge devices.

        The method scans for available USB-SIO bridge devices that match the specified
        configuration and creates interface instances for communication.

        :param config: Configuration string identifying SPI or I2C SIO interface
                       and could filter out USB devices.
        :param timeout: Read timeout in milliseconds, defaults to 5000.
        :return: List of USB-SIO interface instances.
        """
        devices = UsbSioI2CDevice.scan(config, timeout)
        spi_devices = [x for x in devices if isinstance(x, UsbSioI2CDevice)]
        return [cls(device) for device in spi_devices]


class MbootUsbSioSPIInterface(MbootUsbSioInterface):
    """SPSDK MBoot USB-SIO SPI interface implementation.

    This class provides SPI communication interface for MBoot protocol over USB-SIO
    bridge devices, enabling secure provisioning operations through SPI transport.

    :cvar FRAME_START_NOT_READY_LIST: Valid frame start bytes indicating device not ready state.
    :cvar identifier: String identifier for this interface type.
    """

    # START_NOT_READY may be 0x00 or 0xFF depending on the implementation
    FRAME_START_NOT_READY_LIST = [0x00, 0xFF]
    device: UsbSioSPIDevice
    identifier = "usbsio_spi"

    def __init__(self, device: UsbSioSPIDevice) -> None:
        """Initialize the UsbSioSPIDevice object.

        :param device: The UsbSioSPIDevice instance to be used for SPI communication.
        """
        super().__init__(device)

    @classmethod
    def scan(cls, config: str, timeout: Optional[int] = None) -> list[Self]:
        """Scan connected USB-SIO bridge devices.

        The method scans for available USB-SIO bridge devices that match the specified
        configuration and filters them to return only SPI-compatible devices.

        :param config: Configuration string identifying SPI or I2C SIO interface
                       and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of USB-SIO interface instances
        """
        devices = UsbSioSPIDevice.scan(config, timeout)
        spi_devices = [x for x in devices if isinstance(x, UsbSioSPIDevice)]
        return [cls(device) for device in spi_devices]
