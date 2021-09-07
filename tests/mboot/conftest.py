#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from os import path

import pytest

from spsdk.mboot import McuBoot, scan_usb

from .device_config import DevConfig
from .virtual_device import VirtualDevice


def pytest_addoption(parser):
    parser.addoption(
        "--target",
        action="store",
        default="VIRTUAL",
        help="Device: VIRTUAL, IMXRT, ... or 'VID:PID'",
    )


@pytest.fixture(scope="module")
def target(request):
    return request.config.getoption("--target")


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
        device = VirtualDevice(config=config)
    else:
        devs = scan_usb(target)
        if not devs:
            raise Exception(f"Device {target} not connected")
        device = devs[0]
    return device


@pytest.fixture(scope="module")
def mcuboot(device):
    mb = McuBoot(device)
    mb.open()
    yield mb
    mb.close()
