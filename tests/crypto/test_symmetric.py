#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK symmetric cryptography tests.

This module contains unit tests for symmetric encryption and decryption
functionality provided by the SPSDK crypto.symmetric module, including
AES key wrapping/unwrapping, AES CTR mode operations, and SM4 CBC encryption.
"""

from binascii import unhexlify

from spsdk.crypto.symmetric import (
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_key_unwrap,
    aes_key_wrap,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)


def test_aes_key_wrap() -> None:
    """Test AES key wrap functionality.

    Verifies that the AES key wrap algorithm correctly wraps a plain key using
    a key encryption key (KEK) and produces the expected wrapped key result.
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
    """Test AES CTR mode encryption functionality.

    Verifies that the AES CTR encryption implementation produces the expected
    cipher text output for a given key, plaintext, and nonce combination.
    Uses predefined test vectors to validate the encryption algorithm.
    """
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0a" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_cipher_text = aes_ctr_encrypt(key, plain_text, nonce)
    assert calc_cipher_text == cipher_text


def test_aes_ctr_decrypt() -> None:
    """Test AES CTR mode decryption functionality.

    Verifies that the AES CTR decryption function correctly decrypts cipher text
    using a known key and nonce, comparing the result against expected plain text.

    :raises AssertionError: When decrypted text doesn't match expected plain text.
    """
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0a" * 16
    cipher_text = b'\x90\xe2\xf7\x08\xb9J"\x80\x04q\xb5\xfa\xfa\xb0^\xdc'
    calc_plain_text = aes_ctr_decrypt(key, cipher_text, nonce)
    assert calc_plain_text == plain_text


def test_aes_sm4_encrypt() -> None:
    """Test AES SM4 encryption functionality.

    Verifies that the SM4 CBC encryption algorithm produces the expected
    cipher text when encrypting a known plain text with a predefined key
    and nonce. This test ensures the correctness of the SM4 encryption
    implementation by comparing the calculated result against a reference
    cipher text value.
    """
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0a" * 16
    cipher_text = b"\xb1\x0ca\xa0\x1en\xe5>c\xf7e?\xb0\xa4\x1e\xd7"
    calc_cipher_text = sm4_cbc_encrypt(key, plain_text, nonce)
    assert calc_cipher_text == cipher_text


def test_aes_sm4_decrypt() -> None:
    """Test SM4 CBC decryption functionality.

    Verifies that the SM4 CBC decryption function correctly decrypts a known
    cipher text using a predefined key and nonce, and produces the expected
    plain text output.

    :raises AssertionError: If decrypted plain text doesn't match expected result.
    """
    key = b"1234567812345678"
    nonce = b"\x00" * 16
    plain_text = b"\x0a" * 16
    cipher_text = b"\xb1\x0ca\xa0\x1en\xe5>c\xf7e?\xb0\xa4\x1e\xd7"
    calc_plain_text = sm4_cbc_decrypt(key, cipher_text, nonce)
    assert calc_plain_text == plain_text
