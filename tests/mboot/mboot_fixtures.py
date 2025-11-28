#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK MBoot test fixtures and utilities.

This module provides pytest fixtures for testing MBoot functionality,
including device configuration, USB interface setup, and McuBoot instance
creation for automated testing scenarios.
"""

from os import path
from typing import Generator, Optional, cast

import pytest

from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.mcuboot import McuBoot

from .device_config import DevConfig
from .virtual_device import VirtualDevice, VirtualMbootInterface


@pytest.fixture(scope="module")
def target(request: pytest.FixtureRequest) -> str:
    """Get target configuration from pytest request.

    Retrieves the target option value from pytest command line arguments.
    If the target option is not provided or invalid, defaults to "VIRTUAL".

    :param request: Pytest fixture request object containing configuration options.
    :raises ValueError: When the target option cannot be retrieved from config.
    :return: Target name string, either from command line option or "VIRTUAL" as default.
    """
    try:
        return request.config.getoption("--target")
    except ValueError:
        return "VIRTUAL"


@pytest.fixture(scope="module")
def config(target: str) -> Optional[DevConfig]:  # pylint: disable=redefined-outer-name
    """Get device configuration for the specified target.

    Loads device configuration from YAML files located in the devices directory.
    Currently supports VIRTUAL target with virtual_device.yaml configuration.

    :param target: Target device identifier (e.g., "VIRTUAL").
    :return: Device configuration object if target is supported, None otherwise.
    """
    devices_dir = path.join(path.dirname(path.abspath(__file__)), "devices")
    if target == "VIRTUAL":
        return DevConfig(path.join(devices_dir, "virtual_device.yaml"))

    return None


@pytest.fixture(scope="module")
def device(  # pylint: disable=redefined-outer-name
    target: str, config: Optional[DevConfig]
) -> VirtualMbootInterface:
    """Create device interface based on target specification.

    Creates either a virtual mboot interface for testing purposes or connects to
    a physical USB device based on the target parameter.

    :param target: Target device identifier - "VIRTUAL" for virtual device or USB device identifier.
    :param config: Device configuration required for virtual devices, optional for physical devices.
    :raises ConnectionError: When specified USB device is not connected.
    :raises AssertionError: When config is missing for virtual device or target is empty for USB device.
    :return: Virtual mboot interface instance for device communication.
    """
    if target == "VIRTUAL":
        assert config
        interface = VirtualMbootInterface(VirtualDevice(config))
    else:
        assert target
        devs = MbootUSBInterface.scan(target)
        if not devs:
            raise ConnectionError(f"Device {target} not connected")
        interface = cast(VirtualMbootInterface, devs[0])
    return interface


@pytest.fixture(scope="module")
def mcuboot(
    device: VirtualMbootInterface,  # pylint: disable=redefined-outer-name
) -> Generator[McuBoot, None, None]:
    """Create and manage McuBoot instance for testing.

    This fixture creates a McuBoot instance with the provided virtual device interface,
    opens the connection, yields the instance for testing, and ensures proper cleanup
    by closing the connection when done.

    :param device: Virtual MBoot interface to use for communication.
    :return: Generator yielding configured McuBoot instance.
    """
    mb = McuBoot(device)  # type: ignore
    mb.open()
    yield mb
    mb.close()
