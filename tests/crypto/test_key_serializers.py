#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

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

PRIVATE_ENCODINGS = [SPSDKEncoding.DER, SPSDKEncoding.PEM]
PUBLIC_ENCODINGS = [SPSDKEncoding.DER, SPSDKEncoding.PEM, SPSDKEncoding.NXP]


def test_ecc_serializer(tmpdir: str) -> None:
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
    for level in PrivateKeyDilithium.SUPPORTED_LEVELS:
        prk = PrivateKeyDilithium.generate_key(level=level)
        puk = prk.get_public_key()

        prk.save(f"{tmpdir}/prk_{level}.bin")
        prk2 = PrivateKey.load(f"{tmpdir}/prk_{level}.bin")
        assert prk == prk2

        puk.save(f"{tmpdir}/puk_{level}.bin")
        puk2 = PublicKey.load(f"{tmpdir}/puk_{level}.bin")
        assert puk == puk2
