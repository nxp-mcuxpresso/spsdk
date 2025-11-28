#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK HMAC cryptographic functionality tests.

This module contains unit tests for the SPSDK HMAC (Hash-based Message
Authentication Code) implementation, verifying correct HMAC generation
and error handling for invalid inputs.
"""

from binascii import unhexlify

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.exceptions import SPSDKError
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_hmac() -> None:
    """Test HMAC SHA256 calculation against expected value.

    Verifies that the HMAC calculation using SHA256 algorithm produces
    the correct hash for a given key and plaintext by comparing against
    a pre-calculated expected result.

    :raises AssertionError: When calculated HMAC does not match expected value.
    """
    key = b"12345678"
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_hmac_sha256 = unhexlify("d785d886a750c999aa86802697dd4a9934facac72614cbfa66bbf657b74eb1d5")
    calc_hmac_sha256 = hmac(key, plain_text, EnumHashAlgorithm.SHA256)
    assert calc_hmac_sha256 == text_hmac_sha256


def test_hmac_invalid() -> None:
    """Test HMAC function with invalid hash algorithm.

    This test verifies that the HMAC function properly raises an SPSDKError
    when provided with an unsupported hash algorithm enum value.

    :raises SPSDKError: When an invalid/unsupported hash algorithm is provided.
    """

    class TestEnumHashAlgorithm(SpsdkEnum):
        """Test enumeration for hash algorithms used in HMAC testing.

        This enumeration defines hash algorithm variants specifically for testing
        HMAC functionality within the SPSDK crypto module.
        """

        SHA256b = (0, "SHA256b", "SHA256b")

    with pytest.raises(SPSDKError):
        hmac(key=b"1", data=b"t", algorithm=TestEnumHashAlgorithm.SHA256b)  # type: ignore
