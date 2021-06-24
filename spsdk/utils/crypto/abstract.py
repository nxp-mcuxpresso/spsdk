#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for base abstract classes."""

from abc import ABC, abstractmethod
from typing import Any


########################################################################################################################
# Abstract Class for Security Backend
########################################################################################################################
class BackendClass(ABC):
    """Abstract Class for Security Backend."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend Name."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Backend Version."""

    @abstractmethod
    def random_bytes(self, length: int) -> bytes:
        """Return a random byte string with specified length.

        :param length: The length in bytes
        """

    @abstractmethod
    def hash(self, data: bytes, algorithm: str = "sha256") -> bytes:
        """Return a HASH from input data with specified algorithm.

        :param data: Input data in bytes
        :param algorithm: Algorithm type for HASH function
        """

    @abstractmethod
    def hmac(self, key: bytes, data: bytes, algorithm: str = "sha256") -> bytes:
        """Return a HMAC from data with specified key and algorithm.

        :param key: The key in bytes format
        :param data: Input data in bytes format
        :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...)
        """

    @abstractmethod
    def aes_key_wrap(self, kek: bytes, key_to_wrap: bytes) -> bytes:
        """Wraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param key_to_wrap: Plain data
        """

    @abstractmethod
    def aes_key_unwrap(self, kek: bytes, wrapped_key: bytes) -> bytes:
        """Unwraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param wrapped_key: Encrypted data
        """

    @abstractmethod
    def aes_ctr_encrypt(self, key: bytes, plain_data: bytes, nonce: bytes) -> bytes:
        """Encrypt plain data with AES in CTR mode.

        :param key: The key for data encryption
        :param plain_data: Input data
        :param nonce: Nonce data with counter value
        """

    @abstractmethod
    def aes_ctr_decrypt(self, key: bytes, encrypted_data: bytes, nonce: bytes) -> bytes:
        """Decrypt encrypted data with AES in CTR mode.

        :param key: The key for data decryption
        :param encrypted_data: Input data
        :param nonce: Nonce data with counter value
        """

    # @abstractmethod
    # def aes_cbc_encrypt(self, key: bytes, plain_data: bytes, iv_data: bytes) -> bytes:
    #     """Encrypt plain data with AES in CBC mode.
    #
    #     :param key: The key for data encryption
    #     :param plain_data: Input data
    #     :param iv_data: Initialization vector data
    #     """
    #
    # @abstractmethod
    # def aes_cbc_decrypt(self, key: bytes, encrypted_data: bytes, iv_data: bytes) -> bytes:
    #     """Decrypt encrypted data with AES in CBC mode.
    #
    #     :param key: The key for data decryption
    #     :param encrypted_data: Input data
    #     :param iv_data: Initialization vector data
    #     """

    def rsa_sign(self, private_key: bytes, data: bytes, algorithm: str = "sha256") -> bytes:
        """Sign input data.

        :param private_key: The private key
        :param data: Input data
        :param algorithm: Used algorithm
        """

    def rsa_verify(
        self,
        pub_key_mod: int,
        pub_key_exp: int,
        signature: bytes,
        data: bytes,
        algorithm: str = "sha256",
    ) -> bool:
        """Verify input data.

        :param pub_key_mod: The private key modulus
        :param pub_key_exp: The private key exponent
        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        """

    def rsa_public_key(self, modulus: int, exponent: int) -> Any:
        """Create RSA public key object from modulus and exponent.

        :param modulus: The RSA public key modulus
        :param exponent: The RSA public key exponent
        """

    def ecc_sign(self, private_key: bytes, data: bytes, algorithm: str = None) -> bytes:
        """Sign data using (EC)DSA.

        :param private_key: ECC private key
        :param data: Data to sign
        :param algorithm: Hash algorithm, if None the hash length is determined from ECC curve size
        :return: Signature, r and s coordinates as bytes
        """

    def ecc_verify(
        self, public_key: bytes, signature: bytes, data: bytes, algorithm: str = None
    ) -> bool:
        """Verify (EC)DSA signature.

        :param public_key: ECC public key
        :param signature: Signature to verify, r and s coordinates as bytes
        :param data: Data to validate
        :param algorithm: Hash algorithm, if None the hash length is determined from ECC curve size
        :return: True if the signature is valid
        :raises SPSDKError: Signature length is invalid
        """


########################################################################################################################
# Abstract Class for Data Classes
########################################################################################################################
# TODO Refactor: this calss should not be part of crypto module
class BaseClass(ABC):
    """Abstract Class for Data Classes."""

    def __eq__(self, obj: Any) -> bool:
        """Check object equality."""
        return isinstance(obj, self.__class__) and vars(obj) == vars(self)

    def __str__(self) -> str:
        """Object description in string format."""

    @abstractmethod
    def info(self) -> str:
        """Object description in string format."""

    @abstractmethod
    def export(self) -> bytes:
        """Serialize object into bytes array."""

    @classmethod
    @abstractmethod
    def parse(cls, data: bytes, offset: int = 0) -> "BaseClass":
        """Deserialize object from bytes array."""
