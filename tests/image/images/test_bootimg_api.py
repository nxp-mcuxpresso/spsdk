#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.image import parse
from spsdk.image.images import BootImgBase, BootImgRT


@pytest.mark.skip
def test_create_image():
    pass


def test_info_image(data_dir):
    with open(os.path.join(data_dir, "imx8qma0mek-sd.bin"), "rb") as f:
        data = f.read()
    img = parse(data)
    assert isinstance(img, BootImgBase)


def test_rt_image_parse(data_dir):
    with open(f"{data_dir}/led_blinky_xip_srec_iar_dcd_unsigned.bin", "rb") as f:
        image_data = f.read()
    boot_image = BootImgRT.parse(image_data)
    boot_image_data = boot_image.export()
    assert image_data == boot_image_data


def test_rt_image_dcd(data_dir):
    with open(f"{data_dir}/led_blinky_xip_srec_iar_dcd_unsigned.bin", "rb") as f:
        image_data = f.read()
    with open(f"{data_dir}/dcd.bin", "rb") as f:
        dcd_data = f.read()

    parsed_dcd = BootImgRT.parse(image_data).dcd.export()
    assert parsed_dcd == dcd_data
