#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.images import BootImgRT


def test_bootimage_rt10xx_basic():
    """Simple test for BootImgRT"""
    img = BootImgRT(0x60000000)
    assert str(img)
    img_data = img.export()
    # test parser returns same result
    img_data2 = BootImgRT.parse(img_data).export()
    assert img_data == img_data2


def test_bootimage_rt10xx_missing_ivt():
    # IVT header not found
    with pytest.raises(SPSDKError):
        BootImgRT.parse(b"00000000")


def test_bootimage_rt10xx_aead_nonce_len():
    """Test `aead_nonce_len`"""
    assert BootImgRT.aead_nonce_len(0) == 13
    assert BootImgRT.aead_nonce_len(0xFFFF) == 13
    assert BootImgRT.aead_nonce_len(0x10000) == 12
    assert BootImgRT.aead_nonce_len(0xFFFFFF) == 12
    assert BootImgRT.aead_nonce_len(0x1000000) == 11


def test_bootimage_rt10xx_add_encrypted_image():
    """Test add_image with encryption parameters"""
    img = BootImgRT(0x20000000)
    test_app_data = bytes([0]) * 1024
    img.add_image(test_app_data, address=0x20000000, dek_key=b"")
    assert len(img.dek_key) == 16
    # test invalid dek key length
    img = BootImgRT(0x20000000)
    with pytest.raises(SPSDKError):
        img.add_image(test_app_data, address=0x20000000, dek_key=b"x")
    # test image already added
    with pytest.raises(SPSDKError):
        img.add_image(test_app_data, address=0x20000000, dek_key=b"0123456789123456")


def test_invalid_image():
    img = BootImgRT(address=0x60000000)
    with pytest.raises(SPSDKError):
        img.add_image(bytes([1]) * 1024, address=0x20000000, dek_key=b"")
    with pytest.raises(SPSDKError):
        img.add_image(bytes([0]) * 1024, address=0x20000000, dek_key=b"\x00\x00\x00")


def test_invalid_export():
    img = BootImgRT(address=0x60000000)
    img.dek_key = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    with pytest.raises(SPSDKError):
        img.export()


def test_invalid_parse():
    with pytest.raises(SPSDKError):
        BootImgRT.parse(stream=5)


def test_bootimage_rt10xx_add_encrypted_image_invalid():
    img = BootImgRT(0x20000000)
    test_app_data = bytes(1024)
    with pytest.raises(SPSDKError, match="Invalid image type"):
        img.add_image(test_app_data, address=0x20000000, img_type=7)
    with pytest.raises(
        SPSDKError, match="entry_addr not detected from image, must be specified explicitly"
    ):
        img.add_image(test_app_data, address=-1)
