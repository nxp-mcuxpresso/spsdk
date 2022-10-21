#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.images import BootImgRT


def test_parse_xmcd(data_dir):
    with open(f"{data_dir}/evkmimxrt1170_xmcd.bin", "rb") as f:
        data = f.read()
    image = BootImgRT.parse(data)
    assert image.xmcd
    assert "XMCD" in image.info()


def test_parse_no_xmcd(data_dir):
    with open(f"{data_dir}/iled_blinky_cm7_dcd.bin", "rb") as f:
        data = f.read()
    image = BootImgRT.parse(data)
    assert image.xmcd is None
    assert "XMCD" not in image.info()
