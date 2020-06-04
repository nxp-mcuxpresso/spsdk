#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for security backend."""

# Used security modules
from secrets import token_bytes
from typing import Any, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Abstract Class Interface
from .abstract import BackendClass


########################################################################################################################
# SPSDK OpenSSL Backend
########################################################################################################################
class Backend(BackendClass):
    """OpenSSL implementation for security backend."""

    @property
    def name(self) -> str:
        """Name of the backend."""
        return 'SPSDK OpenSSL'

    @property
    def version(self) -> str:
        """Version of the backend."""
        return '0.1'

    def random_bytes(self, length: int) -> bytes:
        """Return a random byte string with specified length.

        :param length: The length in bytes
        :return: Random bytes
        """
        return token_bytes(length)

    @staticmethod
    def _get_algorithm(name: str) -> Any:
        """For specified name return hashes algorithm instance.

        :param name: of the algorithm (class name), case insensitive
        :return: instance of algorithm class
        :raise ValueError: if algorithm not found
        """
        algo_cls = getattr(hashes, name.upper(), None)  # hack: get class object by name
        if algo_cls is None:
            raise ValueError(f'Unsupported algorithm: hashes.{name}'.format(name=name.upper()))

        return algo_cls()  # pylint: disable=not-callable

    def hash(self, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Return a HASH from input data with specified algorithm.

        :param data: Input data in bytes
        :param algorithm: Algorithm type for HASH function
        :return: Hash-ed bytes
        :raise ValueError: if algorithm not found
        """
        hash_obj = hashes.Hash(self._get_algorithm(algorithm), default_backend())
        hash_obj.update(data)
        return hash_obj.finalize()

    def hmac(self, key: bytes, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Return a HMAC from data with specified key and algorithm.

        :param key: The key in bytes format
        :param data: Input data in bytes format
        :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...)
        :return: HMAC bytes
        :raise ValueError: if algorithm not found
        """
        hmac_obj = hmac.HMAC(key, self._get_algorithm(algorithm), default_backend())
        hmac_obj.update(data)
        return hmac_obj.finalize()

    def aes_key_wrap(self, kek: bytes, key_to_wrap: bytes) -> bytes:
        """Wraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param key_to_wrap: Plain data
        :return: Wrapped key
        """
        return keywrap.aes_key_wrap(kek, key_to_wrap, default_backend())

    def aes_key_unwrap(self, kek: bytes, wrapped_key: bytes) -> bytes:
        """Unwraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param wrapped_key: Encrypted data
        :return: Un-wrapped key
        """
        return keywrap.aes_key_unwrap(kek, wrapped_key, default_backend())

    def aes_ctr_encrypt(self, key: bytes, plain_data: bytes, nonce: bytes) -> bytes:
        """Encrypt plain data with AES in CTR mode.

        :param key: The key for data encryption
        :param plain_data: Input data
        :param nonce: Nonce data with counter value
        :return: Encrypted data
        """
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
        enc = cipher.encryptor()
        return enc.update(plain_data) + enc.finalize()

    def aes_ctr_decrypt(self, key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
        """Decrypt encrypted data with AES in CTR mode.

        :param key: The key for data decryption
        :param encrypted_data: Input data
        :param nonce: Nonce data with counter value
        :return: Decrypted data
        """
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), default_backend())
        enc = cipher.decryptor()
        return enc.update(encrypted_data) + enc.finalize()

    def rsa_sign(self, priv_key: Union[rsa.RSAPrivateKey, bytes], data: bytes, algorithm: str = 'sha256') -> bytes:
        """Sign input data.

        :param priv_key: The private key: either rsa.RSAPrivateKey or decrypted binary data in PEM format
        :param data: Input data
        :param algorithm: Used algorithm
        :return: Signed data
        :raise ValueError: if algorithm not found
        """
        if isinstance(priv_key, bytes):
            priv_key = serialization.load_pem_private_key(priv_key, None, default_backend())
        assert isinstance(priv_key, rsa.RSAPrivateKey)
        return priv_key.sign(data=data, padding=padding.PKCS1v15(), algorithm=self._get_algorithm(algorithm))

    def rsa_verify(self, pub_key_mod: int, pub_key_exp: int, signature: bytes, data: bytes,
                   algorithm: str = 'sha256') -> bool:
        """Verify input data.

        :param pub_key_mod: The public key modulus
        :param pub_key_exp: The public key exponent
        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        :raise ValueError: if algorithm not found
        """
        public_key = rsa.RSAPublicNumbers(pub_key_exp, pub_key_mod).public_key(default_backend())
        assert isinstance(public_key, rsa.RSAPublicKey)
        try:
            public_key.verify(signature=signature, data=data, padding=padding.PKCS1v15(),
                              algorithm=self._get_algorithm(algorithm))
        except InvalidSignature:
            return False

        return True

    def rsa_public_key(self, modulus: int, exponent: int) -> rsa.RSAPublicKey:
        """Create RSA public key object from modulus and exponent.

        :param modulus: The RSA public key modulus
        :param exponent: The RSA public key exponent
        :return: RSA Key instance
        """
        return rsa.RSAPublicNumbers(exponent, modulus).public_key(default_backend())


########################################################################################################################
# SPSDK OpenSSL Backend instance
########################################################################################################################
openssl_backend = Backend()     # pylint: disable=invalid-name
