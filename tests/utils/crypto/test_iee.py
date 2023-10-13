#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.utils.crypto.iee import (
    Iee,
    IeeKeyBlob,
    IeeKeyBlobAttribute,
    IeeKeyBlobKeyAttributes,
    IeeKeyBlobLockAttributes,
    IeeKeyBlobModeAttributes,
)
from spsdk.utils.misc import align_block, load_binary


def test_iee_keyblob(data_dir):
    """Test generation of key blob for IEE"""
    keyblob_attribute = IeeKeyBlobAttribute(
        IeeKeyBlobLockAttributes.UNLOCK,
        IeeKeyBlobKeyAttributes.CTR256XTS512,
        IeeKeyBlobModeAttributes.AesXTS,
    )

    keyblob = IeeKeyBlob(
        keyblob_attribute,
        0x30001000,
        0x30008000,
        0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F,
        0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F,
    )

    assert str(keyblob)

    iee = Iee()
    iee.add_key_blob(keyblob)

    exported_plain_keyblobs = iee.get_key_blobs()
    plain_keyblobs = load_binary(os.path.join(data_dir, "iee_keyblobs_plain.bin"))

    assert exported_plain_keyblobs == plain_keyblobs

    encrypted = iee.encrypt_key_blobs(
        ibkek1=0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F,
        ibkek2=0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F,
        keyblob_address=0x30000000,
    )

    encrypted_keyblobs = load_binary(os.path.join(data_dir, "iee_keyblobs.bin"))

    assert encrypted == encrypted_keyblobs

    test_plain_image = load_binary(os.path.join(data_dir, "iee_plain_image.bin"))
    encrypted_image = keyblob.encrypt_image(0x30001000, test_plain_image)
    test_data = load_binary(os.path.join(data_dir, "iee_encrypted_image.bin"))

    assert test_data == encrypted_image

    # start address not aligned
    with pytest.raises(SPSDKError):
        keyblob = IeeKeyBlob(
            keyblob_attribute,
            0x30001100,
            0x30008000,
            0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F,
            0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F,
        )


def test_iee_unencrypted(data_dir):
    """Test IEE - image address range does not match to key blob, won't be encrypted"""
    keyblob_attribute = IeeKeyBlobAttribute(
        IeeKeyBlobLockAttributes.UNLOCK,
        IeeKeyBlobKeyAttributes.CTR256XTS512,
        IeeKeyBlobModeAttributes.AesXTS,
    )

    keyblob = IeeKeyBlob(
        keyblob_attribute,
        0x30001000,
        0x30008000,
        0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F,
        0x202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F,
    )

    iee = Iee()
    iee.add_key_blob(keyblob)
    assert iee[0] == keyblob

    image = align_block(load_binary(os.path.join(data_dir, "boot_image.bin")), 512)
    encrypted = iee.encrypt_image(image, 0x0800FFF)

    assert image == encrypted


def test_keyblob_invalid():
    attribute = IeeKeyBlobAttribute(
        IeeKeyBlobLockAttributes.UNLOCK,
        IeeKeyBlobKeyAttributes.CTR256XTS512,
        IeeKeyBlobModeAttributes.AesXTS,
    )

    with pytest.raises(SPSDKError, match="Invalid start/end address"):
        IeeKeyBlob(attribute, start_addr=0x08001000, end_addr=0x08000000)
