#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from os import path

import pytest

from spsdk.mboot.interfaces.usb import MbootUSBInterface
from spsdk.mboot.mcuboot import McuBoot

from .device_config import DevConfig
from .virtual_device import VirtualDevice, VirtualMbootInterface


@pytest.fixture(scope="module")
def target(request):
    try:
        return request.config.getoption("--target")
    except ValueError:
        return "VIRTUAL"


@pytest.fixture(scope="module")
def config(target):
    devices_dir = path.join(path.dirname(path.abspath(__file__)), "devices")
    if target == "VIRTUAL":
        config = DevConfig(path.join(devices_dir, "virtual_device.yaml"))
    else:
        config = None
    return config


@pytest.fixture(scope="module")
def device(target, config):
    if target == "VIRTUAL":
        interface = VirtualMbootInterface(VirtualDevice(config))
    else:
        devs = MbootUSBInterface.scan(target)
        if not devs:
            raise Exception(f"Device {target} not connected")
        interface = devs[0]
    return interface


@pytest.fixture(scope="module")
def mcuboot(device):
    mb = McuBoot(device)
    mb.open()
    yield mb
    mb.close()
