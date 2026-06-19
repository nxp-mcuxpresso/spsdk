#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK symmetric cryptography tests.

This module contains unit tests for symmetric encryption and decryption
functionality provided by the SPSDK crypto.symmetric module, including
AES key wrapping/unwrapping, AES CTR mode operations, and SM4 CBC encryption.
"""

from binascii import unhexlify

import pytest

from spsdk.crypto.cmac import cmac, cmac_validate
from spsdk.crypto.symmetric import (
    Counter,
    aes_cbc_decrypt,
    aes_cbc_encrypt,
    aes_ccm_decrypt,
    aes_ccm_encrypt,
    aes_ctr_decrypt,
    aes_ctr_encrypt,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    aes_key_unwrap,
    aes_key_wrap,
    sm4_cbc_decrypt,
    sm4_cbc_encrypt,
)
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness


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


def test_cmac_validate_valid() -> None:
    """Test cmac_validate returns True for correct signature."""
    key = b"\x00" * 16
    data = b"hello world test"
    signature = cmac(key, data)
    assert cmac_validate(key, data, signature) is True


def test_cmac_validate_invalid() -> None:
    """Test cmac_validate returns False for incorrect signature ()."""
    key = b"\x00" * 16
    data = b"hello world test"
    wrong_sig = b"\xff" * 16
    assert cmac_validate(key, data, wrong_sig) is False


def test_cmac_basic() -> None:
    """Test cmac produces deterministic output."""
    key = b"\x01" * 16
    data = b"test data"
    result1 = cmac(key, data)
    result2 = cmac(key, data)
    assert result1 == result2
    assert len(result1) == 16


def test_counter_basic() -> None:
    """Test Counter initialization and value property."""
    nonce = b"\x00" * 12 + b"\x00\x00\x00\x01"
    ctr = Counter(nonce)
    val = ctr.value
    assert len(val) == 16


def test_counter_with_ctr_value() -> None:
    """Test Counter with explicit ctr_value offset ()."""
    nonce = b"\xaa" * 12 + b"\x00\x00\x00\x05"
    ctr = Counter(nonce, ctr_value=10, ctr_byteorder_encoding=Endianness.LITTLE)
    val = ctr.value
    assert len(val) == 16


def test_counter_increment() -> None:
    """Test Counter.increment ()."""
    nonce = b"\x00" * 12 + b"\x00\x00\x00\x00"
    ctr = Counter(nonce)
    val_before = ctr.value
    ctr.increment()
    val_after = ctr.value
    assert val_before != val_after


def test_counter_increment_by_value() -> None:
    """Test Counter.increment with custom value."""
    nonce = b"\x00" * 16
    ctr = Counter(nonce)
    ctr.increment(5)
    assert ctr.value[-4:] == (5).to_bytes(4, "little")


def test_counter_invalid_nonce() -> None:
    """Test Counter raises SPSDKError for non-16-byte nonce (error branch)."""
    with pytest.raises(SPSDKError):
        Counter(b"\x00" * 15)


def test_counter_big_endian() -> None:
    """Test Counter with big-endian byte order."""
    nonce = b"\x00" * 12 + b"\x00\x00\x00\x01"
    ctr = Counter(nonce, ctr_byteorder_encoding=Endianness.BIG)
    val = ctr.value
    assert len(val) == 16


def test_aes_key_wrap_and_unwrap() -> None:
    """Test round-trip aes_key_wrap / aes_key_unwrap."""
    kek = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    key = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    wrapped = aes_key_wrap(kek, key)
    assert wrapped != key
    unwrapped = aes_key_unwrap(kek, wrapped)
    assert unwrapped == key


def test_aes_cbc_roundtrip() -> None:
    """Test AES CBC encrypt/decrypt round-trip."""
    key = b"\x00" * 16
    data = b"test data block!"  # 16 bytes
    encrypted = aes_cbc_encrypt(key, data)
    decrypted = aes_cbc_decrypt(key, encrypted)
    assert decrypted == data


def test_aes_cbc_encrypt_invalid_key() -> None:
    """Test AES CBC encrypt with invalid key length raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_cbc_encrypt(b"\x00" * 7, b"data")


def test_aes_cbc_encrypt_invalid_iv() -> None:
    """Test AES CBC encrypt with invalid IV length raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_cbc_encrypt(b"\x00" * 16, b"data", iv_data=b"\x00" * 5)


def test_aes_cbc_decrypt_invalid_key() -> None:
    """Test AES CBC decrypt with invalid key raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_cbc_decrypt(b"\x00" * 7, b"\x00" * 16)


def test_aes_cbc_decrypt_invalid_iv() -> None:
    """Test AES CBC decrypt with invalid IV raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_cbc_decrypt(b"\x00" * 16, b"\x00" * 16, iv_data=b"\x00" * 5)


def test_aes_ccm_roundtrip() -> None:
    """Test AES-CCM encrypt/decrypt round-trip."""
    key = b"\x00" * 16
    nonce = b"\x00" * 11
    plain = b"secret message!"
    aad = b"header"
    encrypted = aes_ccm_encrypt(key, plain, nonce, aad)
    decrypted = aes_ccm_decrypt(key, encrypted, nonce, aad)
    assert decrypted == plain


def test_aes_ccm_encrypt_no_aad() -> None:
    """Test AES-CCM encrypt without associated data."""
    key = b"\x00" * 16
    nonce = b"\x00" * 11
    plain = b"data"
    result = aes_ccm_encrypt(key, plain, nonce)
    assert len(result) > 0


def test_aes_gcm_roundtrip() -> None:
    """Test AES-GCM encrypt/decrypt round-trip."""
    key = b"\x00" * 16
    plain = b"gcm test message"
    encrypted = aes_gcm_encrypt(key, plain)
    # GCM appends 16-byte tag
    iv = b"\x00" * 12
    decrypted = aes_gcm_decrypt(key, encrypted, iv)
    assert decrypted == plain


def test_aes_gcm_encrypt_invalid_key() -> None:
    """Test AES-GCM encrypt with invalid key raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_gcm_encrypt(b"\x00" * 7, b"data")


def test_aes_gcm_encrypt_invalid_iv() -> None:
    """Test AES-GCM encrypt with invalid IV raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_gcm_encrypt(b"\x00" * 16, b"data", init_vector=b"\x00" * 5)


def test_aes_gcm_decrypt_invalid_key() -> None:
    """Test AES-GCM decrypt with invalid key raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_gcm_decrypt(b"\x00" * 7, b"\x00" * 32, b"\x00" * 12)


def test_aes_gcm_decrypt_invalid_iv() -> None:
    """Test AES-GCM decrypt with invalid IV raises SPSDKError."""
    with pytest.raises(SPSDKError):
        aes_gcm_decrypt(b"\x00" * 16, b"\x00" * 32, b"\x00" * 5)


def test_aes_gcm_decrypt_auth_failure() -> None:
    """Test AES-GCM decrypt with tampered data raises SPSDKError."""
    key = b"\x00" * 16
    iv = b"\x00" * 12
    with pytest.raises(SPSDKError):
        aes_gcm_decrypt(key, b"\xff" * 32, iv)


def test_aes_gcm_with_aad() -> None:
    """Test AES-GCM encrypt/decrypt with associated data."""
    key = b"\x01" * 16
    iv = b"\x02" * 12
    plain = b"message"
    aad = b"authenticated header"
    encrypted = aes_gcm_encrypt(key, plain, init_vector=iv, associated_data=aad)
    decrypted = aes_gcm_decrypt(key, encrypted, iv, associated_data=aad)
    assert decrypted == plain


try:
    from spsdk.crypto.lms import IS_LMS_SUPPORTED

    if IS_LMS_SUPPORTED:
        from pyhsslms import LmsPrivateKey

        from spsdk.crypto.lms import LMSParams  # type: ignore[attr-defined]

        _LMS_AVAILABLE = True
    else:
        _LMS_AVAILABLE = False
except Exception:
    _LMS_AVAILABLE = False


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_repr() -> None:
    """Test LMSParams.__repr__ ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    r = repr(p)
    assert "sha256" in r
    assert "32" in r


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_get_lmots_lms_param() -> None:
    """Test get_lmots_param and get_lms_param ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    lmots = p.get_lmots_param()
    lms = p.get_lms_param()
    assert lmots is not None
    assert lms is not None


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_key_lengths() -> None:
    """Test get_private_key_length and get_public_key_length ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    priv_len = p.get_private_key_length()
    pub_len = p.get_public_key_length()
    assert priv_len > 0
    assert pub_len > 0


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_generate_private_key() -> None:
    """Test LMSParams.generate_private_key ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    key = p.generate_private_key()
    assert isinstance(key, LmsPrivateKey)


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_from_key() -> None:
    """Test LMSParams.from_key with private key ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    key = p.generate_private_key()
    p2 = LMSParams.from_key(key)
    assert p2.hash_length == 32
    assert p2.height == 5


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_from_key_public() -> None:
    """Test LMSParams.from_key with public key ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    priv_key = p.generate_private_key()
    pub_key = priv_key.publicKey()
    p2 = LMSParams.from_key(pub_key)
    assert p2.hash_length == 32


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_from_data_too_short() -> None:
    """Test LMSParams.from_data with insufficient data raises SPSDKError."""
    from spsdk.exceptions import SPSDKError

    with pytest.raises(SPSDKError, match="Insufficient"):
        LMSParams.from_data(b"\x00" * 4)


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_from_data_valid() -> None:
    """Test LMSParams.from_data with valid data ()."""
    # Use from_params first to get valid param integers, then construct data
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    key = p.generate_private_key()
    # key data starts with lms_type (4 bytes) + lmots_type (4 bytes)
    key_data = bytes(key.lms_type) + bytes(key.lmots_type) + b"\x00" * 16
    p2 = LMSParams.from_data(key_data)
    assert p2 is not None


@pytest.mark.skipif(not _LMS_AVAILABLE, reason="pyhsslms not available")
def test_lms_params_calc_signature_length() -> None:
    """Test LMSParams.calc_signature_length ()."""
    p = LMSParams(hash_alg="sha256", hash_length=32, height=5, w=1)
    key = p.generate_private_key()
    sig_len = LMSParams.calc_signature_length(key)
    assert sig_len > 0
