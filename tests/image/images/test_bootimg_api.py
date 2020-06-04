#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2018 Martin Olejar
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.image import parse
from spsdk.image.images import BootImgBase


@pytest.mark.skip
def test_create_image():
    pass


def test_info_image(data_dir):
    with open(os.path.join(data_dir, 'imx8qma0mek-sd.bin'), 'rb') as f:
        data = f.read()
    img = parse(data)
    assert isinstance(img, BootImgBase)


