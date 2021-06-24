#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.utils.crypto import KeyBlob, Otfad


def test_otfad_keyblob(data_dir):
    """ Test generation of key blob for OTFAD """
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
    assert key_blob.info()

    # test image encryption
    with open(os.path.join(data_dir, "boot_image.bin"), "rb") as f:
        plain_image = f.read()
    encr_image = key_blob.encrypt_image(0x08001000, plain_image, True)
    with open(os.path.join(data_dir, "otfad_image.bin"), "rb") as f:
        otfad_image = f.read()
    assert encr_image == otfad_image

    # check key blob is created with random bytes for zero_fill and crc
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    gen_blob = key_blob.export(kek=bytes.fromhex("50F66BB4F23B855DCD8FEFC0DA59E963"))
    assert gen_blob != keyblob_bin

    # start address not aligned
    with pytest.raises(ValueError):
        KeyBlob(start_addr=0x08001001, end_addr=0x0800F3FF, key=key, counter_iv=counter)

    # end address not aligned
    with pytest.raises(ValueError):
        KeyBlob(start_addr=0x08001000, end_addr=0x0800F000, key=key, counter_iv=counter)

    # address of the image is not within key blob
    key_blob = KeyBlob(start_addr=0x08001000, end_addr=0x0800F3FF, key=key, counter_iv=counter)
    with pytest.raises(ValueError):
        key_blob.encrypt_image(0x8000000, plain_image, True)
    with pytest.raises(ValueError):
        key_blob.encrypt_image(0x800F000, plain_image, True)


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
    with pytest.raises(ValueError):
        key_blob.encrypt_image(0x0, image, True)

    encr_image = otfad.encrypt_image(image, 0x08001000, True)
    otfad.encrypt_image(image, 0x08001000, False)  # TODO finish the test
    with open(os.path.join(data_dir, "otfad_image.bin"), "rb") as f:
        otfad_image = f.read()
    assert encr_image == otfad_image

    otfad.info()
