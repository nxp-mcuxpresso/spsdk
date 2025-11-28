#!/usr/bin/env python
# -*- coding: utf-8 -*-
## Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK HAB MAC functionality tests.

This module contains unit tests for the HAB (High Assurance Boot) MAC
(Message Authentication Code) implementation in SPSDK.
"""

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.image.hab.hab_mac import MAC


def test_mac_class() -> None:
    """Test MAC class functionality and data handling.

    Validates MAC class initialization with different versions, proper size calculation,
    string representation, and data manipulation including nonce and MAC value extraction.
    Tests error handling for invalid data assignments.

    :raises SPSDKError: When invalid data is assigned to MAC instance.
    """
    mac = MAC(version=0x40)

    assert mac.size == 8 + 16
    assert str(mac)

    test_nonce = b"0123456789123"
    test_mac = b"fedcba9876543210"
    mac = MAC(version=0x42, nonce_len=13, mac_len=16, data=test_nonce + test_mac)
    assert mac.size == 8 + 13 + 16
    assert mac.data == test_nonce + test_mac
    assert mac.nonce == test_nonce
    assert mac.mac == test_mac
    mac.data = test_nonce + test_mac
    assert mac.data == test_nonce + test_mac
    assert mac.nonce == test_nonce
    assert mac.mac == test_mac

    with pytest.raises(SPSDKError):
        mac.data = test_mac


def test_mac_invalid() -> None:
    """Test MAC class with invalid parameters.

    Validates that MAC class properly raises SPSDKError exceptions when provided
    with incorrect parameter values including invalid MAC length, nonce length,
    and MAC bytes count.

    :raises SPSDKError: When MAC length is incorrect (not 16 bytes).
    :raises SPSDKError: When nonce length is incorrect (not 12 bytes).
    :raises SPSDKError: When MAC bytes count doesn't match expected length.
    """
    mac = MAC()
    with pytest.raises(SPSDKError, match="Incorrect length of mac"):
        mac.update_aead_encryption_params(mac=bytes(4), nonce=bytes(12))
    with pytest.raises(SPSDKError, match="Incorrect length of nonce"):
        mac.update_aead_encryption_params(mac=bytes(16), nonce=bytes(4))
    mac = MAC(mac_len=15)
    with pytest.raises(SPSDKError, match="Incorrect number of MAC bytes"):
        mac.update_aead_encryption_params(mac=bytes(16), nonce=bytes(12))
