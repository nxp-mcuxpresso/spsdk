#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.utils.crypto.otfad import KeyBlob, Otfad
from spsdk.utils.misc import align_block


def test_otfad_keyblob(data_dir):
    """Test generation of key blob for OTFAD"""
    # generate key blob using random keys
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF)
    gen_blob = key_blob.export(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))
    assert gen_blob is not None
    # generate key blob using fixed keys
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    counter = bytes.fromhex("5689fab8b4bfb264")
    zeros = bytes(4)  # zero_fill and crc are '0' just for this test; in reality should be random
    key_blob = KeyBlob(
        start_addr=0x08001000,
        end_addr=0x0800F3FF,
        key=key,
        counter_iv=counter,
        zero_fill=zeros,
        crc=zeros,
    )
    gen_blob = key_blob.export(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))

    with open(os.path.join(data_dir, "otfad_keyblob.bin"), "rb") as f:
        keyblob_bin = f.read()
    assert gen_blob == keyblob_bin

    # check that info produces non-empty text
    assert str(key_blob)

    # test image encryption
    with open(os.path.join(data_dir, "boot_image.bin"), "rb") as f:
        plain_image = f.read()
    encr_image = key_blob.encrypt_image(0x08001000, align_block(plain_image, 512), True)
    with open(os.path.join(data_dir, "otfad_image.bin"), "rb") as f:
        otfad_image = f.read()
    assert encr_image == otfad_image

    # check key blob is created with random bytes for zero_fill and crc
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    gen_blob = key_blob.export(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))
    assert gen_blob != keyblob_bin

    # start address not aligned
    with pytest.raises(SPSDKError):
        KeyBlob(start_addr=0x08001001, end_addr=0x0800F3FF, key=key, counter_iv=counter)

    # Support dual image boot, remove test cases for images not withing key blob
    # address of the image is not within key blob
    # key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    # with pytest.raises(SPSDKError):
    #     key_blob.encrypt_image(0x8000000, plain_image, True)
    # with pytest.raises(SPSDKError):
    #     key_blob.encrypt_image(0x800F000, plain_image, True)
    # with pytest.raises(SPSDKError, match="Invalid start address"):
    #     key_blob.encrypt_image(0x800F001, plain_image, True)


def test_otfad(data_dir):
    """Test OTFAD generator"""
    otfad = Otfad()
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    counter = bytes.fromhex("5689fab8b4bfb264")
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    otfad.add_key_blob(key_blob)
    assert otfad[0] == key_blob
    with open(os.path.join(data_dir, "boot_image.bin"), "rb") as f:
        image = f.read()

    # invalid address
    # [SPSDK-1464] Support dual image boot
    # with pytest.raises(SPSDKError):
    #     key_blob.encrypt_image(0x0, image, True)

    encr_image = otfad.encrypt_image(align_block(image, 512), 0x08001000, True)
    otfad.encrypt_image(align_block(image, 512), 0x08001000, False)  # TODO finish the test
    with open(os.path.join(data_dir, "otfad_image.bin"), "rb") as f:
        otfad_image = f.read()
    assert encr_image == otfad_image

    str(otfad)


def test_oftad_invalid(data_dir):
    """Test OTFAD - image address range does not match to key blob, won't be encrypted"""
    otfad = Otfad()
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    counter = bytes.fromhex("5689fab8b4bfb264")
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    otfad.add_key_blob(key_blob)
    assert otfad[0] == key_blob
    with open(os.path.join(data_dir, "boot_image.bin"), "rb") as f:
        image = align_block(f.read(), 512)

    encrypted = otfad.encrypt_image(image, 0x0800FFF, True)
    assert image == encrypted


def test_keyblob_invalid():
    with pytest.raises(SPSDKError, match="Invalid start/end address"):
        KeyBlob(start_addr=0x08001000, end_addr=0x08000000)
    key = bytes.fromhex("B1")
    counter_iv = bytes.fromhex("53")
    with pytest.raises(SPSDKError, match="Invalid key"):
        KeyBlob(key=key, counter_iv=counter_iv, start_addr=0x08001000, end_addr=0x0800F3FF)
    with pytest.raises(SPSDKError, match="key_flags exceeds mask "):
        KeyBlob(start_addr=0x08000000, end_addr=0x080003FF, key_flags=0x8)
    counter = bytes.fromhex("5689fab8b4bfb264")
    key = bytes.fromhex("B1A0C56AF31E98CD6936A79D9E6F829D")
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    with pytest.raises(SPSDKError, match="Invalid length of kek"):
        key_blob.export(kek=bytes(15))
    with pytest.raises(SPSDKError, match="Invalid value crc"):
        key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x080013FF, crc=bytes(5))
        key_blob.export(kek=bytes(16))
    with pytest.raises(SPSDKError, match="Invalid value"):
        key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x080013FF, zero_fill=bytes(5))
        key_blob.export(kek=bytes(16))
    with pytest.raises(SPSDKError, match="Invalid length of initialization vector"):
        key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x080013FF)
        key_blob.export(kek=bytes(16), iv=bytes(32))
    with pytest.raises(SPSDKError, match="Invalid length of data to be encrypted"):
        key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x080013FF)
        key_blob._EXPORT_NBLOCKS_5 = 90
        key_blob.export(kek=bytes(16))
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x080013FF, counter_iv=bytes(8))
    key_blob.ctr_init_vector = bytes(99)
    with pytest.raises(SPSDKError, match="Invalid length of counter init"):
        key_blob._get_ctr_nonce()
