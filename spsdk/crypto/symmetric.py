#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK symmetric cryptography utilities.

This module provides a comprehensive set of functions for symmetric encryption
and decryption operations using various AES modes and SM4 algorithm. It includes
support for key wrapping, block cipher modes (ECB, CBC, CTR, XTS), and
authenticated encryption modes (CCM, GCM).
"""


# Used security modules
from typing import Optional

from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives.ciphers import Cipher, aead, algorithms, modes

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness, align_block


class Counter:
    """AES counter with specified counter byte ordering and customizable increment.

    This class manages a 16-byte counter for AES encryption operations, providing
    control over byte ordering and counter incrementation. The counter consists of
    a 12-byte nonce and a 4-byte counter value that can be incremented as needed.
    """

    @property
    def value(self) -> bytes:
        """Get the initial vector for AES encryption.

        Combines the nonce with the counter value to create the complete initialization vector
        used for AES encryption operations.

        :return: Complete initialization vector as bytes combining nonce and counter.
        """
        return self._nonce + self._ctr.to_bytes(4, self._ctr_byteorder_encoding.value)

    def __init__(
        self,
        nonce: bytes,
        ctr_value: Optional[int] = None,
        ctr_byteorder_encoding: Endianness = Endianness.LITTLE,
    ):
        """Initialize AES counter mode cipher.

        Initializes the counter mode cipher with a 16-byte nonce where the last four bytes
        serve as the initial counter value. The counter can be further adjusted with an
        additional offset value.

        :param nonce: 16-byte nonce where last four bytes are used as initial counter value
        :param ctr_value: Optional counter offset added to the counter value from nonce
        :param ctr_byteorder_encoding: Byte order encoding for counter value conversion
        :raises SPSDKError: When nonce is not exactly 16 bytes long
        """
        if not (isinstance(nonce, bytes) and len(nonce) == 16):
            raise SPSDKError("nonce must be 16 bytes long")
        self._nonce = nonce[:-4]
        self._ctr_byteorder_encoding = ctr_byteorder_encoding
        self._ctr = int.from_bytes(nonce[-4:], ctr_byteorder_encoding.value)
        if ctr_value is not None:
            self._ctr += ctr_value

    def increment(self, value: int = 1) -> None:
        """Increment counter by specified value.

        :param value: Value to add to counter.
        """
        self._ctr += value


def aes_key_wrap(kek: bytes, key_to_wrap: bytes) -> bytes:
    """Wrap a key using AES key wrapping algorithm with a key-encrypting key (KEK).

    This function implements the AES key wrap algorithm as defined in RFC 3394,
    which provides a secure method for encrypting cryptographic keys using another key.

    :param kek: The key-encrypting key used to wrap the target key.
    :param key_to_wrap: The cryptographic key data to be wrapped.
    :return: The wrapped key as bytes.
    """
    return keywrap.aes_key_wrap(kek, key_to_wrap)


def aes_key_unwrap(kek: bytes, wrapped_key: bytes) -> bytes:
    """Unwrap a key using AES key wrapping algorithm with key-encrypting key (KEK).

    This method implements the AES key unwrapping algorithm as defined in RFC 3394
    to securely unwrap a previously wrapped cryptographic key.

    :param kek: The key-encrypting key used for unwrapping.
    :param wrapped_key: The wrapped key data to be unwrapped.
    :return: The unwrapped key as bytes.
    """
    return keywrap.aes_key_unwrap(kek, wrapped_key)


def aes_ecb_encrypt(key: bytes, plain_data: bytes) -> bytes:
    """Encrypt plain data with AES in ECB mode.

    :param key: The encryption key in bytes format.
    :param plain_data: Input data to be encrypted.
    :return: Encrypted data in bytes format.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # nosec
    enc = cipher.encryptor()
    return enc.update(plain_data) + enc.finalize()


def aes_ecb_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    """Decrypt encrypted data with AES in ECB mode.

    :param key: The AES encryption key used for data decryption.
    :param encrypted_data: The encrypted input data to be decrypted.
    :return: Decrypted data as bytes.
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # nosec
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()


def aes_cbc_encrypt(key: bytes, plain_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Encrypt plain data with AES in CBC mode.

    The function performs AES encryption using Cipher Block Chaining (CBC) mode with PKCS7
    padding. If no initialization vector is provided, a zero-filled IV is used.

    :param key: AES encryption key, must be valid AES key length (128, 192, or 256 bits).
    :param plain_data: Raw data to be encrypted.
    :param iv_data: Initialization vector for CBC mode, defaults to zero-filled block.
    :raises SPSDKError: Invalid key length or IV length.
    :return: Encrypted data with PKCS7 padding applied.
    """
    if len(key) * 8 not in algorithms.AES.key_sizes:
        raise SPSDKError(
            "The key must be a valid AES key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.AES.block_size // 8)
    if len(init_vector) * 8 != algorithms.AES.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.AES.block_size // 8}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
    enc = cipher.encryptor()
    return (
        enc.update(align_block(plain_data, alignment=algorithms.AES.block_size // 8))
        + enc.finalize()
    )


def aes_cbc_decrypt(key: bytes, encrypted_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Decrypt encrypted data with AES in CBC mode.

    The function performs AES decryption using Cipher Block Chaining (CBC) mode with
    optional initialization vector. If no IV is provided, a zero-filled IV is used.

    :param key: The AES key for data decryption (must be valid AES key length).
    :param encrypted_data: The encrypted input data to be decrypted.
    :param iv_data: Initialization vector data (optional, defaults to zero-filled).
    :raises SPSDKError: Invalid key length or initialization vector length.
    :return: Decrypted data as bytes.
    """
    if len(key) * 8 not in algorithms.AES.key_sizes:
        raise SPSDKError(
            "The key must be a valid AES key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.AES.block_size // 8)
    if len(init_vector) * 8 != algorithms.AES.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.AES.block_size}")
    cipher = Cipher(algorithms.AES(key), modes.CBC(init_vector))
    dec = cipher.decryptor()
    return dec.update(encrypted_data) + dec.finalize()


def aes_ctr_encrypt(key: bytes, plain_data: bytes, nonce: bytes) -> bytes:
    """Encrypt plain data with AES in CTR mode.

    :param key: The encryption key in bytes format.
    :param plain_data: Input data to be encrypted.
    :param nonce: Nonce data with counter value for CTR mode.
    :return: Encrypted data in bytes format.
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.encryptor()
    return enc.update(plain_data) + enc.finalize()


def aes_ctr_decrypt(key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
    """Decrypt data using AES algorithm in CTR mode.

    This function performs AES decryption in Counter (CTR) mode, which is a stream cipher mode
    that turns a block cipher into a stream cipher by repeatedly encrypting successive values
    of a counter.

    :param key: AES encryption key (must be 16, 24, or 32 bytes for AES-128/192/256).
    :param encrypted_data: The encrypted data to be decrypted.
    :param nonce: Nonce value with counter for CTR mode (typically 16 bytes for AES).
    :return: Decrypted plaintext data as bytes.
    """
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()


def aes_xts_encrypt(key: bytes, plain_data: bytes, tweak: bytes) -> bytes:
    """Encrypt plain data with AES in XTS mode.

    The XTS mode is designed for encrypting data on storage devices where
    the same plaintext might be encrypted multiple times with different tweaks.

    :param key: The encryption key (must be 32 or 64 bytes for AES-128 or AES-256).
    :param plain_data: Input data to be encrypted.
    :param tweak: The tweak value (must be exactly 16 bytes).
    :return: Encrypted data.
    """
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    enc = cipher.encryptor()
    return enc.update(plain_data) + enc.finalize()


def aes_xts_decrypt(key: bytes, encrypted_data: bytes, tweak: bytes) -> bytes:
    """Decrypt encrypted data with AES in XTS mode.

    The XTS mode is designed for encrypting data on storage devices where the same
    plaintext is encrypted to different ciphertext based on its logical position.

    :param key: The encryption key used for AES decryption.
    :param encrypted_data: The encrypted data to be decrypted.
    :param tweak: The 16-byte tweak value used in XTS mode for sector addressing.
    :return: Decrypted plaintext data.
    """
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    enc = cipher.decryptor()
    return enc.update(encrypted_data) + enc.finalize()


def aes_ccm_encrypt(
    key: bytes, plain_data: bytes, nonce: bytes, associated_data: bytes = b"", tag_len: int = 16
) -> bytes:
    """Encrypt plain data with AES in CCM mode (Counter with CBC-MAC).

    AES-CCM provides both confidentiality and authenticity for the encrypted data.
    The method combines the plaintext with associated data for authentication.

    :param key: The encryption key for AES algorithm.
    :param plain_data: Input data to be encrypted.
    :param nonce: Nonce value used for counter initialization.
    :param associated_data: Additional data for authentication (not encrypted).
    :param tag_len: Length of the authentication tag in bytes.
    :return: Encrypted data with authentication tag appended.
    """
    aesccm = aead.AESCCM(key, tag_length=tag_len)
    return aesccm.encrypt(nonce, plain_data, associated_data)


def aes_ccm_decrypt(
    key: bytes, encrypted_data: bytes, nonce: bytes, associated_data: bytes, tag_len: int = 16
) -> bytes:
    """Decrypt data using AES in CCM mode (Counter with CBC-MAC).

    AES-CCM provides both confidentiality and authenticity for the encrypted data.
    The method decrypts the input data and verifies the authentication tag.

    :param key: AES key for decryption (16, 24, or 32 bytes).
    :param encrypted_data: Data to be decrypted including authentication tag.
    :param nonce: Nonce value for CCM mode (7-13 bytes).
    :param associated_data: Additional authenticated data (not encrypted).
    :param tag_len: Authentication tag length in bytes (default 16).
    :raises InvalidTag: If authentication verification fails.
    :raises ValueError: If key, nonce, or tag length is invalid.
    :return: Decrypted plaintext data.
    """
    aesccm = aead.AESCCM(key, tag_length=tag_len)
    return aesccm.decrypt(nonce, encrypted_data, associated_data)


def sm4_cbc_encrypt(key: bytes, plain_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Encrypt plain data with SM4 in CBC mode.

    The method encrypts input data using SM4 algorithm in CBC (Cipher Block Chaining) mode.
    If no initialization vector is provided, a zero-filled IV is used. Input data is
    automatically padded to block size alignment.

    :param key: The key for SM4 encryption, must be valid SM4 key length.
    :param plain_data: Input data to be encrypted.
    :param iv_data: Initialization vector data, defaults to zero-filled if None.
    :raises SPSDKError: Invalid key length or IV length.
    :return: Encrypted data.
    """
    if len(key) * 8 not in algorithms.SM4.key_sizes:
        raise SPSDKError(
            "The key must be a valid SM4 key length: "
            f"{', '.join([str(k) for k in algorithms.SM4.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.SM4.block_size // 8)
    if len(init_vector) * 8 != algorithms.SM4.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.SM4.block_size // 8}")
    cipher = Cipher(algorithms.SM4(key), modes.CBC(init_vector))
    enc = cipher.encryptor()
    return (
        enc.update(align_block(plain_data, alignment=algorithms.SM4.block_size // 8))
        + enc.finalize()
    )


def sm4_cbc_decrypt(key: bytes, encrypted_data: bytes, iv_data: Optional[bytes] = None) -> bytes:
    """Decrypt encrypted data with SM4 in CBC mode.

    :param key: The key for data decryption.
    :param encrypted_data: Input data to be decrypted.
    :param iv_data: Initialization vector data, defaults to zero-filled block if None.
    :raises SPSDKError: Invalid key length or initialization vector length.
    :return: Decrypted data.
    """
    if len(key) * 8 not in algorithms.SM4.key_sizes:
        raise SPSDKError(
            "The key must be a valid SM4 key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = iv_data or bytes(algorithms.SM4.block_size)
    if len(init_vector) * 8 != algorithms.SM4.block_size:
        raise SPSDKError(f"The initial vector length must be {algorithms.SM4.block_size}")
    cipher = Cipher(algorithms.SM4(key), modes.CBC(init_vector))
    dec = cipher.decryptor()
    return dec.update(encrypted_data) + dec.finalize()


def aes_gcm_encrypt(
    key: bytes, plain_data: bytes, init_vector: Optional[bytes] = None, associated_data: bytes = b""
) -> bytes:
    """Encrypt plain data with AES in GCM mode (Galois/Counter Mode).

    The method uses AES-GCM encryption which provides both confidentiality and authenticity.
    The authentication tag is automatically appended to the encrypted data.

    :param key: The AES encryption key (must be 128, 192, or 256 bits).
    :param plain_data: Input data to be encrypted.
    :param init_vector: Initialization vector (nonce), defaults to 12 zero bytes if None.
    :param associated_data: Additional authenticated data that remains unencrypted.
    :return: Encrypted data with authentication tag appended.
    :raises SPSDKError: Invalid key length or initialization vector length.
    """
    if len(key) * 8 not in algorithms.AES.key_sizes:
        raise SPSDKError(
            "The key must be a valid AES key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    init_vector = init_vector or bytes(12)
    if len(init_vector) != 12:
        raise SPSDKError("The initial vector length must be 12 Bytes long")

    aesgcm = aead.AESGCM(key)
    return aesgcm.encrypt(init_vector, plain_data, associated_data)


def aes_gcm_decrypt(
    key: bytes,
    encrypted_data: bytes,
    init_vector: bytes,
    associated_data: bytes = b"",
) -> bytes:
    """Decrypt encrypted data with AES in GCM mode (Galois/Counter Mode).

    The method decrypts data that was encrypted using AES-GCM algorithm. The encrypted data
    must include the authentication tag appended at the end. The method validates the key
    length and initialization vector before performing decryption.

    :param key: The key for data decryption (16, 24, or 32 bytes for AES-128/192/256)
    :param encrypted_data: Input data with authentication tag appended
    :param init_vector: Initialization vector (nonce) - must be exactly 12 bytes
    :param associated_data: Associated data - unencrypted but authenticated data
    :return: Decrypted data as bytes
    :raises SPSDKError: Invalid key length, IV length, or authentication failure
    """
    if len(key) * 8 not in algorithms.AES.key_sizes:
        raise SPSDKError(
            "The key must be a valid AES key length: "
            f"{', '.join([str(k) for k in algorithms.AES.key_sizes])}"
        )
    if len(init_vector) != 12:
        raise SPSDKError("The initial vector length must be 12 Bytes long")
    aesgcm = aead.AESGCM(key)
    try:
        return aesgcm.decrypt(init_vector, encrypted_data, associated_data)
    except Exception as e:
        raise SPSDKError(f"AES-GCM decryption failed: {str(e)}") from e
