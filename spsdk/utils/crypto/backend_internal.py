#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Internal implementation for security backend."""
import importlib
from struct import pack, unpack_from
from typing import Any, Union

# Used security modules
from Crypto import Random, Hash
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# Abstract Class Interface
from .abstract import BackendClass


########################################################################################################################
# SPSDK Backend
########################################################################################################################
class Backend(BackendClass):
    """Internal implementation for security backend."""

    @property
    def name(self) -> str:
        """Name of the backend."""
        return 'SPSDK'

    @property
    def version(self) -> str:
        """Version of the backend."""
        return '0.1'

    def random_bytes(self, length: int) -> bytes:
        """Return a random byte string with specified length.

        :param length: The length in bytes
        :return: Random bytes
        """
        return Random.get_random_bytes(length)

    @staticmethod
    def _get_algorithm(name: str, data: bytes) -> Any:
        """For specified name return Hash algorithm instance.

        :param name: Name of the algorithm (class name), case insensitive
        :param data: parameter for the constructor of the algorithm class
        :return: instance of algorithm class
        :raise ValueError: if the algorithm is not found
        """
        # algo_cls = getattr(Hash, name.upper(), None)  # hack: get class object by name
        algo_cls = importlib.import_module(f'Crypto.Hash.{name.upper()}')
        if algo_cls is None:
            raise ValueError(f'Unsupported algorithm: Hash.{name}'.format(name=name.upper()))
        return algo_cls.new(data)  # type: ignore  # pylint: disable=not-callable

    def hash(self, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Return a HASH from input data with specified algorithm.

        :param data: Input data in bytes
        :param algorithm: Algorithm type for HASH function
        :return: Hash-ed bytes
        :raise ValueError: if the algorithm is not found
        """
        return self._get_algorithm(algorithm, data).digest()

    def hmac(self, key: bytes, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Return a HMAC from data with specified key and algorithm.

        :param key: The key in bytes format
        :param data: Input data in bytes format
        :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...)
        :return: HMAC bytes
        :raise ValueError: if the algorithm is not found
        """
        cls = getattr(Hash, algorithm.upper(), None)
        if cls is None:
            raise ValueError()
        hmac_obj = HMAC.new(key, data, cls)
        return hmac_obj.digest()

    # pylint: disable=invalid-name
    def aes_key_wrap(self, kek: bytes, key_to_wrap: bytes) -> bytes:
        """Wraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param key_to_wrap: Plain data
        :return: Wrapped key
        :raise ValueError: Invalid length of kek or key_to_wrap
        """
        if len(kek) not in (16, 24, 32):
            raise ValueError("The wrapping key must be a valid AES key length")
        if len(key_to_wrap) < 16:
            raise ValueError("The key to wrap must be at least 16 bytes")
        if len(key_to_wrap) % 8 != 0:
            raise ValueError("The key to wrap must be a multiple of 8 bytes")
        iv = 0xa6a6a6a6a6a6a6a6
        n = len(key_to_wrap) // 8
        r = [b''] + [key_to_wrap[i * 8: i * 8 + 8] for i in range(0, n)]
        a = iv
        aes = AES.new(kek, AES.MODE_ECB)
        for j in range(6):
            for i in range(1, n + 1):
                b = aes.encrypt(pack('>Q', a) + r[i])
                a = unpack_from('>Q', b[:8])[0] ^ (n * j + i)
                r[i] = b[8:]
        return pack('>Q', a) + b''.join(r[1:])

    # pylint: disable=invalid-name
    def aes_key_unwrap(self, kek: bytes, wrapped_key: bytes) -> bytes:
        """Unwraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param wrapped_key: Encrypted data
        :return: Un-wrapped key
        :raise ValueError: Invalid length of kek or key_to_wrap
        """
        if len(kek) not in (16, 24, 32):
            raise ValueError("The wrapping key must be a valid AES key length")
        if len(wrapped_key) < 24:
            raise ValueError("Must be at least 24 bytes")
        if len(wrapped_key) % 8 != 0:
            raise ValueError("The wrapped key must be a multiple of 8 bytes")
        # default iv
        iv = 0xa6a6a6a6a6a6a6a6
        n = len(wrapped_key) // 8 - 1
        # NOTE: R[0] is never accessed, left in for consistency with RFC indices
        r = [b''] + [wrapped_key[i * 8: i * 8 + 8] for i in range(1, n + 1)]
        a = unpack_from('>Q', wrapped_key[:8])[0]
        aes = AES.new(kek, AES.MODE_ECB)
        for j in range(5, -1, -1):  # counting down
            for i in range(n, 0, -1):  # (n, n-1, ..., 1)
                b = aes.decrypt(pack('>Q', a ^ (n * j + i)) + r[i])
                a = unpack_from('>Q', b[:8])[0]
                r[i] = b[8:]
        if a != iv:
            raise ValueError(f"Integrity Check Failed: {a:016X} (expected {iv:016X})")
        return b''.join(r[1:])

    def aes_ctr_encrypt(self, key: bytes, plain_data: bytes, nonce: bytes) -> bytes:
        """Encrypt plain data with AES in CTR mode.

        :param key: The key for data encryption
        :param plain_data: Input data
        :param nonce: Nonce data with counter value
        :return: Encrypted data
        :raise ValueError: Invalid length of key or nonce
        """
        if len(key) not in (16, 24, 32):
            raise ValueError("The key must be a valid AES key length")
        if len(nonce) != 16:
            raise ValueError("The nonce length is not valid")
        assert len(plain_data) <= len(nonce)
        aes = AES.new(key, AES.MODE_ECB)
        ctr = aes.encrypt(nonce)
        return bytes([p ^ c for p, c in zip(plain_data, ctr)])

    def aes_ctr_decrypt(self, key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
        """Decrypt encrypted data with AES in CTR mode.

        :param key: The key for data decryption
        :param encrypted_data: Input data
        :param nonce: Nonce data with counter value
        :return: Decrypted data
        """
        return self.aes_ctr_encrypt(key, encrypted_data, nonce)

    def rsa_sign(self, private_key: Union[RSA.RsaKey, bytes], data: bytes, algorithm: str = 'sha256') -> bytes:
        """Sign input data.

        :param private_key: The private key: either RSA.RsaKey or decrypted binary data in PEM format
        :param data: Input data
        :param algorithm: Used algorithm
        :return: Singed data
        :raise ValueError: if the algorithm is not found
        """
        if isinstance(private_key, bytes):
            private_key = RSA.import_key(private_key)
        assert isinstance(private_key, RSA.RsaKey)
        h = self._get_algorithm(algorithm, data)
        return pkcs1_15.new(private_key).sign(h)

    def rsa_verify(self, pub_key_mod: int, pub_key_exp: int, signature: bytes, data: bytes,
                   algorithm: str = 'sha256') -> bool:
        """Verify input data.

        :param pub_key_mod: The public key modulus
        :param pub_key_exp: The public key exponent
        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        :raise ValueError: if the algorithm is not found
        """
        public_key = self.rsa_public_key(pub_key_mod, pub_key_exp)
        assert isinstance(public_key, RSA.RsaKey)
        h = self._get_algorithm(algorithm, data)
        try:
            pkcs1_15.new(public_key).verify(h, signature)
        except (ValueError, TypeError):
            return False

        return True

    def rsa_public_key(self, modulus: int, exponent: int) -> RSA.RsaKey:
        """Create RSA public key object from modulus and exponent.

        :param modulus: The RSA public key modulus
        :param exponent: The RSA public key exponent
        :return: RSA Key instance
        """
        return RSA.construct((modulus, exponent))


########################################################################################################################
# SPSDK Backend instance
########################################################################################################################
internal_backend = Backend()    # pylint: disable=invalid-name
