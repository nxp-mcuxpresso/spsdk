#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB utilities testing module.

This module contains unit tests for the HAB (High Assurance Boot) utilities
functionality, specifically testing address detection and entry point
resolution capabilities.
"""

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
def test_hab_app_address_autodetection(data_dir: str, app_image: str, app_address: str) -> None:
    """Test HAB application address auto-detection functionality.

    Verifies that the HAB utility can correctly auto-detect the entry point address
    from an application image file by comparing the detected address with the
    expected address value.

    :param data_dir: Directory path containing test configuration files.
    :param app_image: Path to the application image file to analyze.
    :param app_address: Expected entry point address as hexadecimal string.
    """
    config = Config.create_from_file(os.path.join(data_dir, "test_app_address.yaml"))
    config["inputImageFile"] = app_image
    entrypoint = get_entrypoint_address(config)
    assert entrypoint == int(app_address, 16)
