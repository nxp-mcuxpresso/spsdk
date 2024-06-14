#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

pytest.importorskip("gmssl")

from spsdk.crypto.crypto_types import SPSDKEncoding
from spsdk.crypto.keys import PrivateKeySM2, PublicKeySM2
from spsdk.crypto.oscca import SM2Encoder, sanitize_pem
from spsdk.utils.misc import load_binary


@pytest.mark.parametrize(
    "in_file, out_file",
    [
        ("openssl_sm2_private.pem", "openssl_sm2_private_custom.der"),
        ("openssl_sm2_private_custom.der", "openssl_sm2_private_custom.der"),
        ("openssl_sm2_public.pem", "openssl_sm2_public_custom.der"),
        ("openssl_sm2_public_custom.der", "openssl_sm2_public_custom.der"),
    ],
)
def test_sanitize(data_dir: str, in_file: str, out_file: str):
    in_data = load_binary(f"{data_dir}/{in_file}")
    expected = load_binary(f"{data_dir}/{out_file}")
    assert sanitize_pem(in_data) == expected


@pytest.mark.parametrize(
    "key_file",
    [
        "openssl_sm2_private.pem",
        "openssl_sm2_private_custom.der",
    ],
)
def test_private_key_loaders(data_dir: str, key_file: str):
    key_path = f"{data_dir}/{key_file}"
    prk = PrivateKeySM2.load(key_path)
    puk = PrivateKeySM2.load(key_path).get_public_key()

    assert isinstance(prk, PrivateKeySM2)
    assert isinstance(puk, PublicKeySM2)
    assert prk.get_public_key() == puk


@pytest.mark.parametrize(
    "key_file",
    [
        "openssl_sm2_public.pem",
        "openssl_sm2_public_custom.der",
    ],
)
def test_public_key_loaders(data_dir: str, key_file: str):
    key_path = f"{data_dir}/{key_file}"

    puk = PublicKeySM2.load(key_path)
    puk2 = PublicKeySM2.load(key_path)

    assert isinstance(puk, PublicKeySM2)
    assert isinstance(puk2, PublicKeySM2)

    assert puk == puk2


@pytest.mark.parametrize(
    "key_file",
    [
        "openssl_sm2_private_custom.der",
    ],
)
def test_private_key_encoder(data_dir: str, key_file: str):
    key_path = f"{data_dir}/{key_file}"
    data = load_binary(key_path)
    key_set = SM2Encoder().decode_private_key(data=data)
    key_bytes = SM2Encoder().encode_private_key(key_set)

    assert data == key_bytes


@pytest.mark.parametrize(
    "key_file",
    [
        "openssl_sm2_public_custom.der",
    ],
)
def test_public_key_encoder(data_dir: str, key_file: str):
    key_path = f"{data_dir}/{key_file}"
    data = load_binary(key_path)
    key = SM2Encoder().decode_public_key(data=data)
    key_bytes = SM2Encoder().encode_public_key(key)

    assert data == key_bytes


def test_save_load(tmpdir):
    prk = PrivateKeySM2.generate_key()
    puk = prk.get_public_key()

    prk.save(f"{tmpdir}/private.der", encoding=SPSDKEncoding.DER)
    puk.save(f"{tmpdir}/public.der", encoding=SPSDKEncoding.DER)

    prk2 = PrivateKeySM2.load(f"{tmpdir}/private.der")
    puk2 = PublicKeySM2.load(f"{tmpdir}/public.der")

    assert prk == prk2
    assert puk == puk2


@pytest.mark.parametrize(
    "key_file, signature_file, data_file",
    [
        ("openssl_sm2_private.pem", "message.openssl.sm2", "message.bin"),
        ("openssl_sm2_private_custom.der", "message.openssl.sm2", "message.bin"),
    ],
)
def test_sm2_verify_sign_private(data_dir, key_file, signature_file, data_file):
    private_key = PrivateKeySM2.load(f"{data_dir}/{key_file}")
    signature = load_binary(f"{data_dir}/{signature_file}")
    data = load_binary(f"{data_dir}/{data_file}")
    private_key.get_public_key().verify_signature(signature, data)


@pytest.mark.parametrize(
    "key_file, signature_file, data_file",
    [
        ("openssl_sm2_public.pem", "message.openssl.sm2", "message.bin"),
        ("openssl_sm2_public_custom.der", "message.openssl.sm2", "message.bin"),
    ],
)
def test_sm2_verify_sign_public(data_dir, key_file, signature_file, data_file):
    public_key = PublicKeySM2.load(f"{data_dir}/{key_file}")
    signature = load_binary(f"{data_dir}/{signature_file}")
    data = load_binary(f"{data_dir}/{data_file}")
    public_key.verify_signature(signature, data)


@pytest.mark.parametrize(
    "signing_key_file, verification_key_file",
    [
        ("openssl_sm2_private.pem", "openssl_sm2_private.pem"),
    ],
)
def test_sm2_sign_verify_private(data_dir, signing_key_file, verification_key_file):
    signing_key = PrivateKeySM2.load(f"{data_dir}/{signing_key_file}")
    verification_key = PrivateKeySM2.load(f"{data_dir}/{verification_key_file}")

    message = b"message to sign"

    signature = signing_key.sign(data=message, use_ber=True)
    # sanity check that signature is BER encoded
    assert len(signature) > 64
    assert signature[0] == 0x30
    verification_key.get_public_key().verify_signature(signature=signature, data=message)

    # Test raw signature format r || s
    signature = signing_key.sign(data=message, use_ber=False)
    assert len(signature) == 64
    verification_key.get_public_key().verify_signature(signature=signature, data=message)


@pytest.mark.parametrize(
    "signing_key_file, verification_key_file",
    [
        ("openssl_sm2_private_custom.der", "openssl_sm2_public.pem"),
    ],
)
def test_sm2_sign_verify_public(data_dir, signing_key_file, verification_key_file):
    signing_key = PrivateKeySM2.load(f"{data_dir}/{signing_key_file}")
    verification_key = PublicKeySM2.load(f"{data_dir}/{verification_key_file}")

    message = b"message to sign"

    signature = signing_key.sign(data=message, use_ber=True)
    # sanity check that signature is BER encoded
    assert len(signature) > 64
    assert signature[0] == 0x30
    verification_key.verify_signature(signature=signature, data=message)

    # Test raw signature format r || s
    signature = signing_key.sign(data=message, use_ber=False)
    assert len(signature) == 64
    verification_key.verify_signature(signature=signature, data=message)


def test_generate_random_sm2():
    prk = PrivateKeySM2.generate_key()
    puk = prk.get_public_key()

    message = b"message to sign"
    signature = prk.sign(data=message)
    puk.verify_signature(signature, message)
