#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic key serializers test module.

This module contains comprehensive tests for cryptographic key serialization
and deserialization functionality across different key types and encoding formats
supported by SPSDK, including ECC, RSA, SM2, and Dilithium keys.
"""

import pytest

from spsdk.crypto.keys import (
    IS_DILITHIUM_SUPPORTED,
    IS_OSCCA_SUPPORTED,
    EccCurve,
    PrivateKey,
    PrivateKeyEcc,
    PrivateKeyRsa,
    PublicKey,
    SPSDKEncoding,
)

if IS_OSCCA_SUPPORTED:
    from spsdk.crypto.keys import PrivateKeySM2

if IS_DILITHIUM_SUPPORTED:
    from spsdk.crypto.keys import PrivateKeyDilithium

from spsdk.exceptions import SPSDKUnsupportedOperation

PRIVATE_ENCODINGS = [SPSDKEncoding.DER, SPSDKEncoding.PEM]
PUBLIC_ENCODINGS = [SPSDKEncoding.DER, SPSDKEncoding.PEM, SPSDKEncoding.NXP]


def test_ecc_serializer(tmpdir: str) -> None:
    """Test ECC key serialization and deserialization across all supported curves and encodings.

    This test verifies that ECC private and public keys can be properly saved to and loaded from
    files using various encoding formats. It ensures data integrity by comparing the original
    keys with the loaded keys for equality.

    :param tmpdir: Temporary directory path for storing test key files during serialization tests.
    """
    for curve in EccCurve:
        prk = PrivateKeyEcc.generate_key(curve_name=curve)
        puk = prk.get_public_key()

        for enc in PRIVATE_ENCODINGS:
            file = f"{tmpdir}/prk_{curve.name}.{enc.name}"
            prk.save(file, encoding=enc)
            prk2 = PrivateKey.load(file)
            assert prk == prk2

        for enc in PUBLIC_ENCODINGS:
            file = f"{tmpdir}/puk_{curve.name}.{enc.name}"
            puk.save(file, encoding=enc)
            puk2 = PublicKey.load(file)
            assert puk == puk2


def test_rsa_serializer(tmpdir: str) -> None:
    """Test RSA key serialization and deserialization functionality.

    This test verifies that RSA private and public keys can be correctly saved
    to and loaded from files using various encoding formats. It tests all
    supported RSA key sizes and encoding combinations to ensure serialization
    roundtrip integrity.

    :param tmpdir: Temporary directory path for storing test key files during the test.
    """
    for key_size in PrivateKeyRsa.SUPPORTED_KEY_SIZES:
        prk = PrivateKeyRsa.generate_key(key_size=key_size)
        puk = prk.get_public_key()

        for enc in PRIVATE_ENCODINGS:
            file = f"{tmpdir}/prk_{key_size}.{enc.name}"
            prk.save(file, encoding=enc)
            prk2 = PrivateKey.load(file)
            assert prk == prk2

        for enc in PUBLIC_ENCODINGS:
            file = f"{tmpdir}/puk_{key_size}.{enc.name}"
            puk.save(file, encoding=enc)
            puk2 = PublicKey.load(file)
            assert puk == puk2


@pytest.mark.skipif(not IS_OSCCA_SUPPORTED, reason="OSCCA support is not installed")
def test_sm2_serializer(tmpdir: str) -> None:
    """Test SM2 key serialization and deserialization functionality.

    Validates that SM2 private and public keys can be properly saved to and loaded from
    DER format files, ensuring data integrity through round-trip serialization.

    :param tmpdir: Temporary directory path for storing test key files.
    """
    prk = PrivateKeySM2.generate_key()
    puk = prk.get_public_key()

    prk.save(f"{tmpdir}/prk.der")
    prk2 = PrivateKey.load(f"{tmpdir}/prk.der")
    assert prk == prk2

    puk.save(f"{tmpdir}/puk.der")
    puk2 = PublicKey.load(f"{tmpdir}/puk.der")
    assert puk == puk2


@pytest.mark.skipif(not IS_DILITHIUM_SUPPORTED, reason="PQC support is not installed")
def test_dilithium_serializer(tmpdir: str) -> None:
    """Test Dilithium key serialization and deserialization functionality.

    This test verifies that Dilithium private keys can be generated, saved to files,
    and loaded back correctly for all supported security levels. It also tests
    public key extraction, serialization, and deserialization when supported.

    :param tmpdir: Temporary directory path for storing test key files.
    """
    for level in PrivateKeyDilithium.SUPPORTED_LEVELS:
        prk = PrivateKeyDilithium.generate_key(level=level)

        prk.save(f"{tmpdir}/prk_{level}.bin")
        prk2 = PrivateKey.load(f"{tmpdir}/prk_{level}.bin")
        assert prk == prk2

        try:
            puk = prk.get_public_key()
            puk.save(f"{tmpdir}/puk_{level}.bin")
            puk2 = PublicKey.load(f"{tmpdir}/puk_{level}.bin")
            assert puk == puk2
        except SPSDKUnsupportedOperation:
            pass  # Some key types might not support public key extraction
