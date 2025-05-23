#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os

import pytest
from spsdk.image.hab.utils import get_entrypoint_address
from spsdk.utils.config import Config


@pytest.mark.parametrize(
    "app_image,app_address",
    [
        ("app_image.srec", "0x30002101"),
        ("app_image.elf", "0x30002101"),
        ("app_image.bin", "0x60003411"),
    ],
)
def test_hab_app_address_autodetection(data_dir, app_image, app_address):
    config = Config.create_from_file(os.path.join(data_dir, "test_app_address.yaml"))
    config["inputImageFile"] = app_image
    entrypoint = get_entrypoint_address(config)
    assert entrypoint == int(app_address, 16)
