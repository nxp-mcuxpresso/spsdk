#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB file cryptographic operations test suite.

This module contains comprehensive tests for cryptographic functionality
used in Secure Binary (SB) file operations, including hashing, HMAC,
AES encryption/decryption, key wrapping, and digital signatures.
"""

import os
from binascii import unhexlify

import pytest

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash
from spsdk.crypto.keys import PrivateKeyEcc, PrivateKeyRsa, PublicKeyEcc
from spsdk.crypto.rng import random_bytes
from spsdk.crypto.spsdk_hmac import hmac
from spsdk.crypto.symmetric import aes_ctr_decrypt, aes_ctr_encrypt, aes_key_unwrap, aes_key_wrap
from spsdk.exceptions import SPSDKError
from spsdk.utils.spsdk_enum import SpsdkEnum


def test_random_bytes() -> None:
    """Test random bytes generation functionality.

    Verifies that the random_bytes function generates proper random byte sequences
    by checking the return type, length, and randomness properties.

    :raises AssertionError: If random bytes generation fails validation checks.
    """
    random = random_bytes(16)
    assert isinstance(random, bytes)
    assert len(random) == 16
    assert random != random_bytes(16)


def test_hash() -> None:
    """Test SHA256 hash calculation functionality.

    Verifies that the get_hash function correctly computes SHA256 hash
    by comparing the calculated hash of a known plain text input against
    the expected hash value.

    :raises AssertionError: If calculated hash doesn't match expected value.
    """
    plain_text = b"testestestestestestestestestestestestestestestestestestestest"
    text_sha256 = unhexlify("41116FE4EFB90A050AABB83419E19BF2196A0E76AB8E3034C8D674042EE23621")
    calc_sha256 = get_hash(plain_text, EnumHashAlgorithm.SHA256)
    assert calc_sha256 == text_sha256


def test_hmac() -> None:
    """Test HMAC SHA256 calculation against known test vector.

    This test verifies that the HMAC implementation correctly computes SHA256-based
    HMAC by comparing the calculated result with a pre-computed expected value
    using a known key and plaintext combination.

    :raises AssertionError: If calculated HMAC does not match expected test vector.
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
        """Test enumeration for hash algorithms used in SBFile crypto operations.

        This enumeration defines hash algorithm constants for testing cryptographic
        functionality within the SBFile module, providing standardized identifiers
        for hash algorithm validation and processing.
        """

        SHA256b = (0, "SHA256b", "SHA256b")

    with pytest.raises(SPSDKError):
        hmac(key=b"1", data=b"t", algorithm=TestEnumHashAlgorithm.SHA256b)  # type: ignore[arg-type]


def test_aes_key_wrap() -> None:
    """Test AES key wrap functionality.

    Verifies that the AES key wrap algorithm correctly wraps a plain key using
    a key encryption key (KEK) and produces the expected wrapped key result.
    Uses predefined test vectors to validate the implementation.

    :raises AssertionError: If the calculated wrapped key doesn't match expected result.
    """
    kek = unhexlify("000102030405060708090A0B0C0D0E0F")
    plain_key = unhexlify("00112233445566778899AABBCCDDEEFF")
    wrapped_key = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    calc_wrapped_key = aes_key_wrap(kek, plain_key)
    assert calc_wrapped_key == wrapped_key


def test_aes_key_unwrap() -> None:
    """Test AES key unwrapping functionality.

    Verifies that the aes_key_unwrap function correctly unwraps a wrapped AES key
    using a known key encryption key (KEK) and validates the result against
    the expected plain key value.
    """
    kek = unhexlify("000102030405060708090A0B0C0D0E0F")
    plain_key = unhexlify("00112233445566778899AABBCCDDEEFF")
    wrapped_key = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    calc_plain_key = aes_key_unwrap(kek, wrapped_key)
    assert calc_plain_key == plain_key


def test_aes_ctr_encrypt() -> None:
    """Test AES CTR encryption functionality.

    Verifies that the AES CTR encryption function produces the expected
    cipher text when given a known key, plaintext, and nonce. This test
    uses predefined test vectors to ensure the encryption implementation
    is working correctly.

    :raises AssertionError: If the calculated cipher text doesn't match expected result.
    """
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0a" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_cipher_text = aes_ctr_encrypt(key, plain_text, nonce)
    assert calc_cipher_text == cipher_text


def test_aes_ctr_decrypt() -> None:
    """Test AES CTR decryption functionality.

    Verifies that the aes_ctr_decrypt function correctly decrypts cipher text
    using AES in Counter (CTR) mode with a given key and nonce. The test uses
    predefined test vectors to ensure the decryption produces the expected
    plain text output.
    """
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0a" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_plain_text = aes_ctr_decrypt(key, cipher_text, nonce)
    assert calc_plain_text == plain_text


def test_rsa_sign(data_dir: str) -> None:
    """Test RSA signature generation and verification.

    This test verifies that the RSA private key can generate a correct signature
    for a given data payload. It loads an RSA 2048-bit private key from a PEM file,
    signs test data, and validates the signature matches the expected result.

    :param data_dir: Directory path containing test data files including the RSA private key.
    """
    private_key = PrivateKeyRsa.load(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"))

    signature = (
        b"\xc2!b\xf9\xb7$<i><2\x07|\x86,\xdd\x003\x93\x95\x1a\x92?\xf5\x1c\xfce\xfd#\x02\x1b\xd5&\xec\xf8`"
        b"\xe1\x1ex\xfd=Ls\xaf\x81\x12[\xe8\x80n\xc17\x8b\x9a\xba\x86N\xcbCd\xfb\xe7\xfei\xcc\x90\x02\xbf)"
        b'\x05\x81\t\xbb\xed+dW\xc8\xb6BG\xb3\x9eW\xc40PUf\xb3\xadU\xf0q\xaf\xe3"\xd5\n\xf9?\x1d\xf6\xd1\xc5'
        b"\xcd\x18\x8b\xe8u\xd7\xa0\n\xfaR4\x1fY|g\xf1\xee\r\xd8\xed\x16D\x19\xcdbo1\x1c\xdeP<H\xcf\x8aT\xae"
        b"\xea\x8d8\xb8\xb7[U,\x1a\x05\xb8\xb6\xbd\xcaWi\xc7\x11\x96s\x16I\xe0\x8a\xdc\xd7\xa3F] \xf7:r"
        b'\x1405y"\xa3\xbf\x97\x94@\xa5\xa4\x8a\xd1\x8d\xb2\x91\x0b\xe2\xd0\x03\xf4=\xeb\x0fT\xa8\x8cn\x9d'
        b";O\xa2eT\xcf\xdffd0?\xbd\xf6\xe2\xb6m\x0b\xe34V5Z\xca\x831\xae\x7f\x94C\x0e<?fI\xf1\xedS\xe8K\xd9"
        b"\xd0S\xf0\xf6\xf5e\xb6\xb1Z\x85\x1e!"
    )
    data = bytes([v % 256 for v in range(0, 512)])
    # specify key using SPSDK_Key class
    calc_signature = private_key.sign(data)
    assert len(calc_signature) == 256
    assert calc_signature == signature


def test_rsa_verify(data_dir: str) -> None:
    """Test RSA signature verification functionality.

    This test verifies that RSA signature verification works correctly by loading
    a private key, using a predefined signature, and testing verification against
    known test data.

    :param data_dir: Directory path containing test data files including the RSA private key file.
    """
    private_key = PrivateKeyRsa.load(os.path.join(data_dir, "selfsign_privatekey_rsa2048.pem"))

    signature = (
        b"\xc2!b\xf9\xb7$<i><2\x07|\x86,\xdd\x003\x93\x95\x1a\x92?\xf5\x1c\xfce\xfd#\x02\x1b\xd5&\xec\xf8`"
        b"\xe1\x1ex\xfd=Ls\xaf\x81\x12[\xe8\x80n\xc17\x8b\x9a\xba\x86N\xcbCd\xfb\xe7\xfei\xcc\x90\x02\xbf)"
        b'\x05\x81\t\xbb\xed+dW\xc8\xb6BG\xb3\x9eW\xc40PUf\xb3\xadU\xf0q\xaf\xe3"\xd5\n\xf9?\x1d\xf6\xd1\xc5'
        b"\xcd\x18\x8b\xe8u\xd7\xa0\n\xfaR4\x1fY|g\xf1\xee\r\xd8\xed\x16D\x19\xcdbo1\x1c\xdeP<H\xcf\x8aT\xae"
        b"\xea\x8d8\xb8\xb7[U,\x1a\x05\xb8\xb6\xbd\xcaWi\xc7\x11\x96s\x16I\xe0\x8a\xdc\xd7\xa3F] \xf7:r"
        b'\x1405y"\xa3\xbf\x97\x94@\xa5\xa4\x8a\xd1\x8d\xb2\x91\x0b\xe2\xd0\x03\xf4=\xeb\x0fT\xa8\x8cn\x9d'
        b";O\xa2eT\xcf\xdffd0?\xbd\xf6\xe2\xb6m\x0b\xe34V5Z\xca\x831\xae\x7f\x94C\x0e<?fI\xf1\xedS\xe8K\xd9"
        b"\xd0S\xf0\xf6\xf5e\xb6\xb1Z\x85\x1e!"
    )
    data = bytes([v % 256 for v in range(0, 512)])
    assert private_key.get_public_key().verify_signature(signature, data)


def test_ecc_sign_verify(data_dir: str) -> None:
    """Test ECC signature generation and verification functionality.

    This test verifies that ECC private keys can generate valid signatures and that
    corresponding public keys can verify those signatures. It also confirms that
    OpenSSL's randomized signature generation produces different signatures for
    the same data while maintaining verification validity.

    :param data_dir: Directory path containing test cryptographic key files.
    """
    private_key = PrivateKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"))
    public_key = PublicKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"))
    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = private_key.sign(data)
    calc_signature2 = private_key.sign(data)
    # openssl utilize randomized signature thus two signatures are different
    assert calc_signature != calc_signature2

    is_valid = public_key.verify_signature(signature=calc_signature, data=data)
    is_valid2 = public_key.verify_signature(signature=calc_signature2, data=data)
    # randomized signatures are still valid
    assert is_valid and is_valid2


def test_ecc_sign_verify_incorrect(data_dir: str) -> None:
    """Test ECC signature verification with malformed signatures.

    This test verifies that the ECC signature verification correctly rejects
    invalid signatures by testing two scenarios: truncated signature and
    oversized signature.

    :param data_dir: Directory path containing test cryptographic key files.
    """
    private_key = PrivateKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_priv_key.pem"))
    public_key = PublicKeyEcc.load(os.path.join(data_dir, "ecc_secp256r1_pub_key.pem"))

    data = b"THIS IS MESSAGE TO BE SIGNED"
    calc_signature = private_key.sign(data)

    # malform the signature
    bad_signature = calc_signature[:-2] + bytes(2)
    is_valid = public_key.verify_signature(signature=bad_signature, data=data)
    assert not is_valid

    # make signature bigger than expected
    bad_signature = calc_signature + bytes(2)
    assert not public_key.verify_signature(signature=bad_signature, data=data)
