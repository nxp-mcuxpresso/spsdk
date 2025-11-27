#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK KeyStore module unit tests.

This module contains comprehensive unit tests for the KeyStore functionality,
including validation of key storage operations, key source type handling,
and error conditions.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.keystore import KeySourceType, KeyStore


def test_empty_key_store() -> None:
    """Test empty KeyStore instances for different key source types.

    Verifies that KeyStore objects can be created with different KeySourceType
    values and that they behave correctly when empty. Tests both KEYSTORE and
    OTP key source types to ensure proper initialization and export functionality.
    """
    key_store = KeyStore(KeySourceType.KEYSTORE)
    assert key_store.key_source == KeySourceType.KEYSTORE
    assert key_store.export() == bytes()
    str(key_store)
    # OTP
    key_store = KeyStore(KeySourceType.OTP)
    assert key_store.key_source == KeySourceType.OTP
    assert key_store.export() == bytes()
    str(key_store)


def test_key_store() -> None:
    """Test KeyStore functionality with basic operations.

    Validates KeyStore initialization with KEYSTORE source type and zero-filled data,
    verifies key source property access, data export functionality, and string
    representation generation.

    :raises AssertionError: If KeyStore properties or export don't match expected values.
    """
    key_store = KeyStore(KeySourceType.KEYSTORE, bytes([0] * KeyStore.KEY_STORE_SIZE))
    assert key_store.key_source == KeySourceType.KEYSTORE
    assert key_store.export() == bytes([0] * KeyStore.KEY_STORE_SIZE)
    str(key_store)


def test_invalid_key_store() -> None:
    """Test invalid KeyStore initialization and method calls.

    Validates that KeyStore properly raises SPSDKError exceptions for:
    - Invalid key store length during initialization
    - Attempting to use key store with OTP key source type
    - Invalid HMAC key length in derive_hmac_key method
    - Invalid master key length in derive_enc_image_key method
    - Invalid master key length in derive_sb_kek_key method
    - Invalid master key length in derive_otfad_kek_key method
    - Invalid OTFAD input length in derive_otfad_kek_key method

    :raises SPSDKError: When KeyStore is initialized or used with invalid parameters
    """
    # invalid key store length
    with pytest.raises(SPSDKError):
        KeyStore(KeySourceType.KEYSTORE, bytes(range(10)))
    # key-store specified in OTP mode
    with pytest.raises(SPSDKError):
        KeyStore(KeySourceType.OTP, bytes(range(10)))
    with pytest.raises(
        SPSDKError, match="KeyStore can be initialized only if key_source == KEYSTORE"
    ):
        KeyStore(KeySourceType.OTP, bytes(1424))
    key_store = KeyStore(KeySourceType.KEYSTORE, bytes([0] * KeyStore.KEY_STORE_SIZE))
    with pytest.raises(SPSDKError, match="Invalid length of hmac key"):
        key_store.derive_hmac_key(hmac_key=bytes(31))
    with pytest.raises(SPSDKError, match="Invalid length of master key"):
        key_store.derive_enc_image_key(master_key=bytes(31))
    with pytest.raises(SPSDKError, match="Invalid length of master key"):
        key_store.derive_sb_kek_key(master_key=bytes(31))
    with pytest.raises(SPSDKError, match="Invalid length of master key"):
        key_store.derive_otfad_kek_key(master_key=bytes(31), otfad_input=bytes(16))
    with pytest.raises(SPSDKError, match="Invalid length of input"):
        key_store.derive_otfad_kek_key(master_key=bytes(32), otfad_input=bytes(15))
