#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKValueError
from spsdk.utils.images import BinaryImage, BinaryPattern


def test_binary_image_sort_sub_images():
    """Simple test of sorting of sub images inside the BinaryImage class"""
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    image.validate()

    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"


def test_binary_image_join_sub_images():
    """Simple test of joining together sub images inside the BinaryImage class"""
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    image.validate()

    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"

    assert len(image.sub_images) == 3

    image.join_images()

    assert len(image.sub_images) == 0

    assert image.binary == b"\x00\x00\x02\x00\x04\x00\x06\x00"
    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"


def test_binary_image_pattern():
    assert BinaryPattern("zeros").get_block(4) == b"\x00\x00\x00\x00"
    assert BinaryPattern("ones").get_block(4) == b"\xff\xff\xff\xff"
    assert len(BinaryPattern("rand").get_block(4)) == 4
    assert BinaryPattern("inc").get_block(4) == b"\x00\x01\x02\x03"


def test_binary_image_invalid_pattern():
    with pytest.raises(SPSDKValueError):
        BinaryPattern("invalid")


def test_binary_image_draw():
    """Simple test of draw the BinaryImage class"""
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    assert "\x1b[" in image.draw()
    assert "\x1b[" not in image.draw(no_color=True)


def test_binary_image_draw_invalid():
    """Simple test of draw invalid binary BinaryImage class"""
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x4, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))

    image.add_image(image_0x2)
    image.add_image(image_0x4)

    assert "\x1b[31m" in image.draw()
