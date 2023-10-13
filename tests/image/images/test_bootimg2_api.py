#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

from spsdk.image.images import BootImg2


def test_create_image_api():
    image = BootImg2()

    assert image.version == 0x41
    assert image.address == 0
    assert image.offset == 0x400
    assert image.size == 44

    data = image.export()
    assert len(data) == 44

    image.add_image(bytes([0x20] * 100))
    assert image.size == 144

    data = image.export()
    assert len(data) == 4000 + 140

    assert str(image)


def test_parse_image_api(data_dir):
    with open(os.path.join(data_dir, "imx7d_uboot.imx"), "rb") as f:
        image = BootImg2.parse(f.read())

    assert isinstance(image, BootImg2)
    assert image.version == 0x40
    assert image.address == 0x877FF000
    assert image.offset == 0x400
    assert image.size == 478208

    assert str(image)
