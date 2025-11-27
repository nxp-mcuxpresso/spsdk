#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test utilities for SPSDK crypto common functionality.

This module contains unit tests for common cryptographic utilities and operations
used across the SPSDK crypto module, including key management and validation.
"""

import os
from typing import Any

import pytest

from spsdk.crypto.keys import EccCurve, PrivateKeyEcc, PrivateKeyRsa, PublicKey
from spsdk.crypto.signature_provider import PlainFileSP
from spsdk.crypto.symmetric import Counter
from spsdk.crypto.utils import get_matching_key_id
from spsdk.exceptions import SPSDKValueError
from spsdk.utils.misc import Endianness


def test_counter() -> None:
    """Test Counter class functionality with various configurations.

    Validates Counter initialization with different nonce values, counter values,
    and byte order encodings. Tests increment operations with single and multiple
    step increments to ensure proper counter behavior.
    """
    # simple counter with nonce only
    cntr = Counter(bytes([0] * 16))
    assert cntr.value == bytes([0] * 16)

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567, ctr_byteorder_encoding=Endianness.LITTLE)
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567)
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as big endian
    cntr = Counter(bytes([0] * 16), ctr_value=1, ctr_byteorder_encoding=Endianness.BIG)
    assert cntr.value == bytes([0] * 15 + [1])

    # increment
    cntr.increment()
    assert cntr.value == bytes([0] * 15 + [2])
    cntr.increment(2)
    assert cntr.value == bytes([0] * 15 + [4])
    cntr.increment(256)
    assert cntr.value == bytes([0] * 14 + [1, 4])


@pytest.mark.parametrize("length", [(2048), (3072), (4096)])
def test_matching_keys_rsa(tmpdir: Any, length: int) -> None:
    """Test RSA key matching functionality with generated keys.

    This test generates multiple RSA private keys, saves them to temporary files,
    creates signature providers from those files, and verifies that the
    get_matching_key_id function correctly identifies which public key corresponds
    to each signature provider.

    :param tmpdir: Temporary directory for storing generated key files.
    :param length: RSA key size in bits for key generation.
    """
    signature_providers = []
    pub_keys: list[PublicKey] = []
    for i in range(4):
        prv_key = PrivateKeyRsa.generate_key(key_size=length)
        prv_key.save(os.path.join(tmpdir, f"key{i}.pem"))
        signature_providers.append(PlainFileSP(os.path.join(tmpdir, f"key{i}.pem")))
        pub_keys.append(prv_key.get_public_key())

    for i in range(4):
        assert i == get_matching_key_id(
            public_keys=pub_keys, signature_provider=signature_providers[i]
        )


@pytest.mark.parametrize("curve", [(curve_name) for curve_name in EccCurve])
def test_matching_keys_ecc(tmpdir: Any, curve: EccCurve) -> None:
    """Test matching ECC keys with signature providers.

    This test verifies that the get_matching_key_id function correctly identifies
    the matching key ID for each signature provider by generating ECC key pairs,
    saving them to files, creating signature providers, and asserting that each
    provider matches its corresponding key index.

    :param tmpdir: Temporary directory for storing generated key files.
    :param curve: ECC curve type to use for key generation.
    """
    signature_providers = []
    pub_keys: list[PublicKey] = []
    for i in range(4):
        prv_key = PrivateKeyEcc.generate_key(curve_name=curve)
        prv_key.save(os.path.join(tmpdir, f"key{i}.pem"))
        signature_providers.append(PlainFileSP(os.path.join(tmpdir, f"key{i}.pem")))
        pub_keys.append(prv_key.get_public_key())

    for i in range(4):
        assert i == get_matching_key_id(
            public_keys=pub_keys, signature_provider=signature_providers[i]
        )


def test_matching_keys_unmatch(tmpdir: Any) -> None:
    """Test that get_matching_key_id raises error when no matching key is found.

    This test verifies that the get_matching_key_id function properly raises
    SPSDKValueError when the signature provider's private key doesn't correspond
    to any of the provided public keys.

    :param tmpdir: Temporary directory for storing test key files.
    """
    signature_providers = []
    pub_keys: list[PublicKey] = []
    for i in range(4):
        prv_key = PrivateKeyRsa.generate_key()
        prv_key.save(os.path.join(tmpdir, f"key{i}.pem"))
        signature_providers.append(PlainFileSP(os.path.join(tmpdir, f"key{i}.pem")))
        pub_keys.append(prv_key.get_public_key())

    prv_key = PrivateKeyRsa.generate_key()
    prv_key.save(os.path.join(tmpdir, "diff_key.pem"))
    with pytest.raises(SPSDKValueError):
        get_matching_key_id(
            public_keys=pub_keys,
            signature_provider=PlainFileSP(os.path.join(tmpdir, "diff_key.pem")),
        )
