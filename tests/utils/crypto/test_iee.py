#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK IEE (Inline Encryption Engine) functionality tests.

This module contains comprehensive test cases for the IEE module functionality,
including keyblob creation, encryption/decryption operations, and error handling
for various IEE configurations and scenarios.
"""

import os

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.iee.iee import (
    Iee,
    IeeKeyBlob,
    IeeKeyBlobAttribute,
    IeeKeyBlobKeyAttributes,
    IeeKeyBlobLockAttributes,
    IeeKeyBlobModeAttributes,
)
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import align_block, load_binary


def test_iee_keyblob(data_dir: str) -> None:
    """Test generation of key blob for IEE.

    This test validates the complete IEE (Inline Encryption Engine) workflow including:
    - Creating key blob with specific attributes and encryption keys
    - Adding key blob to IEE instance and verifying plain key blob export
    - Encrypting key blobs and comparing with expected encrypted data
    - Testing image encryption functionality with the key blob
    - Validating error handling for misaligned start addresses

    :param data_dir: Directory path containing test data files for IEE operations
    """
    keyblob_attribute = IeeKeyBlobAttribute(
        IeeKeyBlobLockAttributes.UNLOCK,
        IeeKeyBlobKeyAttributes.CTR256XTS512,
        IeeKeyBlobModeAttributes.AesXTS,
    )

    keyblob = IeeKeyBlob(
        keyblob_attribute,
        0x30001000,
        0x30008000,
        bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        bytes.fromhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
    )

    assert str(keyblob)

    iee = Iee(
        family=FamilyRevision("mimxrt1176"),
        keyblob_address=0x30000000,
        ibkek1=bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        ibkek2=bytes.fromhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
    )
    iee.add_key_blob(keyblob)

    exported_plain_keyblobs = iee.get_key_blobs()
    plain_keyblobs = load_binary(os.path.join(data_dir, "iee_keyblobs_plain.bin"))

    assert exported_plain_keyblobs == plain_keyblobs

    encrypted = iee.encrypt_key_blobs(
        ibkek1=bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        ibkek2=bytes.fromhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
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
            bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
            bytes.fromhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
        )


def test_iee_unencrypted(data_dir: str) -> None:
    """Test IEE encryption when image address range does not match key blob.

    This test verifies that when an image's address range falls outside the key blob's
    defined address range, the image remains unencrypted. The test creates an IEE
    instance with a key blob covering addresses 0x30001000-0x30008000, then attempts
    to encrypt an image at address 0x0800FFF (outside the range).

    :param data_dir: Directory path containing test data files including boot_image.bin
    """
    keyblob_attribute = IeeKeyBlobAttribute(
        IeeKeyBlobLockAttributes.UNLOCK,
        IeeKeyBlobKeyAttributes.CTR256XTS512,
        IeeKeyBlobModeAttributes.AesXTS,
    )

    keyblob = IeeKeyBlob(
        keyblob_attribute,
        0x30001000,
        0x30008000,
        bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        bytes.fromhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
    )

    iee = Iee(
        family=FamilyRevision("mimxrt1176"),
        keyblob_address=0x30001000,
        ibkek1=bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
        ibkek2=bytes.fromhex("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"),
    )
    iee.add_key_blob(keyblob)
    assert iee[0] == keyblob

    image = align_block(load_binary(os.path.join(data_dir, "boot_image.bin")), 512)
    encrypted = iee.encrypt_image(image, 0x0800FFF)

    assert image == encrypted


def test_keyblob_invalid() -> None:
    """Test invalid keyblob creation with invalid address range.

    This test verifies that creating an IeeKeyBlob with a start address
    greater than the end address raises an SPSDKError with appropriate
    error message.

    :raises SPSDKError: When start address is greater than end address.
    """
    attribute = IeeKeyBlobAttribute(
        IeeKeyBlobLockAttributes.UNLOCK,
        IeeKeyBlobKeyAttributes.CTR256XTS512,
        IeeKeyBlobModeAttributes.AesXTS,
    )

    with pytest.raises(SPSDKError, match="Invalid start/end address"):
        IeeKeyBlob(attribute, start_addr=0x08001000, end_addr=0x08000000)
