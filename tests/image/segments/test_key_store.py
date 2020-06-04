#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.image.keystore import KeySourceType, KeyStore


def test_empty_key_store():
    key_store = KeyStore(KeySourceType.KEYSTORE)
    assert key_store.key_source == KeySourceType.KEYSTORE
    assert key_store.export() == bytes()
    key_store.info()
    # OTP
    key_store = KeyStore(KeySourceType.OTP)
    assert key_store.key_source == KeySourceType.OTP
    assert key_store.export() == bytes()
    key_store.info()


def test_key_store():
    key_store = KeyStore(KeySourceType.KEYSTORE, bytes([0] * KeyStore.KEY_STORE_SIZE))
    assert key_store.key_source == KeySourceType.KEYSTORE
    assert key_store.export() == bytes([0] * KeyStore.KEY_STORE_SIZE)
    key_store.info()


def test_invalid_key_store():
    # invalid key store length
    with pytest.raises(ValueError):
        KeyStore(KeySourceType.KEYSTORE, bytes(range(10)))
    # key-store specified in OTP mode
    with pytest.raises(ValueError):
        KeyStore(KeySourceType.OTP, bytes(range(10)))
