#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK OSCCA cryptographic algorithms test module.

This module contains comprehensive tests for OSCCA (Office of State Commercial Cryptography Administration)
cryptographic implementations in SPSDK, focusing on SM2 elliptic curve cryptography and related utilities.
Tests cover PEM format sanitization, SM2 key operations, digital signature creation and verification,
and key pair generation and serialization.
"""

import pytest

pytest.importorskip("gmssl")

from spsdk.crypto.crypto_types import SPSDKEncoding  # noqa: E402
from spsdk.crypto.keys import PrivateKeySM2, PublicKeySM2  # noqa: E402
from spsdk.crypto.oscca import SM2Encoder, sanitize_pem  # noqa: E402
from spsdk.utils.misc import load_binary  # noqa: E402


@pytest.mark.parametrize(
    "in_file, out_file",
    [
        ("openssl_sm2_private.pem", "openssl_sm2_private_custom.der"),
        ("openssl_sm2_private_custom.der", "openssl_sm2_private_custom.der"),
        ("openssl_sm2_public.pem", "openssl_sm2_public_custom.der"),
        ("openssl_sm2_public_custom.der", "openssl_sm2_public_custom.der"),
    ],
)
def test_sanitize(data_dir: str, in_file: str, out_file: str) -> None:
    """Test PEM sanitization functionality.

    Verifies that the sanitize_pem function correctly processes input PEM data
    by comparing the sanitized output against expected results loaded from test files.

    :param data_dir: Directory path containing test data files.
    :param in_file: Name of the input file containing PEM data to be sanitized.
    :param out_file: Name of the expected output file for comparison.
    """
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
def test_private_key_loaders(data_dir: str, key_file: str) -> None:
    """Test SM2 private key loading functionality.

    Verifies that SM2 private keys can be loaded from files and that the
    corresponding public keys can be derived correctly. Tests both private
    key instantiation and public key derivation consistency.

    :param data_dir: Directory path containing test key files.
    :param key_file: Name of the key file to load and test.
    """
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
def test_public_key_loaders(data_dir: str, key_file: str) -> None:
    """Test SM2 public key loading functionality.

    Verifies that the PublicKeySM2.load method correctly loads SM2 public keys
    from files and that multiple loads of the same key file produce equivalent
    key objects.

    :param data_dir: Directory path containing test data files.
    :param key_file: Name of the key file to load for testing.
    """
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
def test_private_key_encoder(data_dir: str, key_file: str) -> None:
    """Test SM2 private key encoding and decoding functionality.

    Verifies that the SM2Encoder can properly decode a private key from binary data
    and then encode it back to the same binary format, ensuring data integrity
    throughout the encoding/decoding process.

    :param data_dir: Directory path containing the test data files.
    :param key_file: Name of the private key file to test.
    """
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
def test_public_key_encoder(data_dir: str, key_file: str) -> None:
    """Test SM2 public key encoding and decoding functionality.

    Verifies that SM2 public key can be properly decoded from binary data
    and then encoded back to the same binary representation, ensuring
    round-trip consistency.

    :param data_dir: Directory path containing test data files.
    :param key_file: Name of the key file to test.
    """
    key_path = f"{data_dir}/{key_file}"
    data = load_binary(key_path)
    key = SM2Encoder().decode_public_key(data=data)
    key_bytes = SM2Encoder().encode_public_key(key)

    assert data == key_bytes


def test_save_load(tmpdir: str) -> None:
    """Test saving and loading of SM2 private and public keys.

    Verifies that SM2 private and public keys can be saved to DER format files
    and loaded back correctly, maintaining their original values.

    :param tmpdir: Temporary directory path for saving test files.
    """
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
def test_sm2_verify_sign_private(
    data_dir: str, key_file: str, signature_file: str, data_file: str
) -> None:
    """Test SM2 private key signature verification functionality.

    This test verifies that an SM2 private key can be used to derive the corresponding
    public key and successfully verify a signature against given data.

    :param data_dir: Directory path containing test data files.
    :param key_file: Filename of the SM2 private key file to load.
    :param signature_file: Filename of the signature file to verify.
    :param data_file: Filename of the data file that was signed.
    """
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
def test_sm2_verify_sign_public(
    data_dir: str, key_file: str, signature_file: str, data_file: str
) -> None:
    """Test SM2 signature verification with public key.

    Verifies that a given signature is valid for the provided data using
    an SM2 public key loaded from file.

    :param data_dir: Directory path containing test data files.
    :param key_file: Filename of the SM2 public key file.
    :param signature_file: Filename of the signature file to verify.
    :param data_file: Filename of the data file that was signed.
    """
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
def test_sm2_sign_verify_private(
    data_dir: str, signing_key_file: str, verification_key_file: str
) -> None:
    """Test SM2 digital signature with private key signing and verification.

    This test verifies SM2 signature functionality using private keys for both signing
    and verification operations. It tests both BER-encoded and raw signature formats
    to ensure compatibility with different encoding schemes.

    :param data_dir: Directory path containing the test key files
    :param signing_key_file: Filename of the private key used for signing
    :param verification_key_file: Filename of the private key used for verification
    """
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
def test_sm2_sign_verify_public(
    data_dir: str, signing_key_file: str, verification_key_file: str
) -> None:
    """Test SM2 digital signature creation and verification with public key.

    This test verifies the SM2 signing and verification process using separate
    signing and verification keys. It tests both BER-encoded signatures and
    raw signature format (r || s concatenation).

    :param data_dir: Directory path containing the test key files
    :param signing_key_file: Filename of the private key used for signing
    :param verification_key_file: Filename of the public key used for verification
    """
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


def test_generate_random_sm2() -> None:
    """Test SM2 key generation, signing, and verification functionality.

    This test verifies the complete SM2 cryptographic workflow by generating
    a private key, deriving its public key, signing a message, and verifying
    the signature to ensure the implementation works correctly.
    """
    prk = PrivateKeySM2.generate_key()
    puk = prk.get_public_key()

    message = b"message to sign"
    signature = prk.sign(data=message)
    puk.verify_signature(signature, message)
