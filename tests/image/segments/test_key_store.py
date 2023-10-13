#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.keystore import KeySourceType, KeyStore


def test_empty_key_store():
    key_store = KeyStore(KeySourceType.KEYSTORE)
    assert key_store.key_source == KeySourceType.KEYSTORE
    assert key_store.export() == bytes()
    str(key_store)
    # OTP
    key_store = KeyStore(KeySourceType.OTP)
    assert key_store.key_source == KeySourceType.OTP
    assert key_store.export() == bytes()
    str(key_store)


def test_key_store():
    key_store = KeyStore(KeySourceType.KEYSTORE, bytes([0] * KeyStore.KEY_STORE_SIZE))
    assert key_store.key_source == KeySourceType.KEYSTORE
    assert key_store.export() == bytes([0] * KeyStore.KEY_STORE_SIZE)
    str(key_store)


def test_invalid_key_store():
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
