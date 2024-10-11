#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""USBSIO Mboot interface implementation."""
from typing import Optional, Union

from typing_extensions import Self

from spsdk.mboot.protocol.serial_protocol import MbootSerialProtocol, to_int
from spsdk.utils.interfaces.device.usbsio_device import UsbSioI2CDevice, UsbSioSPIDevice


class MbootUsbSioInterface(MbootSerialProtocol):
    """USBSIO interface."""

    device: Union[UsbSioI2CDevice, UsbSioSPIDevice]

    def _wait_for_data(self) -> int:
        """Wait for first "not ready" frame."""
        if not self.device.is_nirq_enabled:
            return super()._wait_for_data()
        self.device.wait_for_nirq_state(state=0)
        return to_int(self.device.read(1))


class MbootUsbSioI2CInterface(MbootUsbSioInterface):
    """USBSIO I2C interface."""

    device: UsbSioI2CDevice
    identifier = "usbsio_i2c"

    def __init__(self, device: UsbSioI2CDevice):
        """Initialize the UsbSioI2CDevice object.

        :param device: The device instance
        """
        super().__init__(device=device)

    @classmethod
    def scan(cls, config: str, timeout: Optional[int] = None) -> list[Self]:
        """Scan connected USB-SIO bridge devices.

        :param config: Configuration string identifying spi or i2c SIO interface
                        and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of interfaces
        """
        devices = UsbSioI2CDevice.scan(config, timeout)
        spi_devices = [x for x in devices if isinstance(x, UsbSioI2CDevice)]
        return [cls(device) for device in spi_devices]


class MbootUsbSioSPIInterface(MbootUsbSioInterface):
    """USBSIO I2C interface."""

    # START_NOT_READY may be 0x00 or 0xFF depending on the implementation
    FRAME_START_NOT_READY_LIST = [0x00, 0xFF]
    device: UsbSioSPIDevice
    identifier = "usbsio_spi"

    def __init__(self, device: UsbSioSPIDevice) -> None:
        """Initialize the UsbSioSPIDevice object.

        :param device: The device instance
        """
        super().__init__(device)

    @classmethod
    def scan(cls, config: str, timeout: Optional[int] = None) -> list[Self]:
        """Scan connected USB-SIO bridge devices.

        :param config: Configuration string identifying spi or i2c SIO interface
                        and could filter out USB devices
        :param timeout: Read timeout in milliseconds, defaults to 5000
        :return: List of interfaces
        """
        devices = UsbSioSPIDevice.scan(config, timeout)
        spi_devices = [x for x in devices if isinstance(x, UsbSioSPIDevice)]
        return [cls(device) for device in spi_devices]
