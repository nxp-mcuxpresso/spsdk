#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Internal implementation for security backend."""
import importlib
import math
from struct import pack, unpack_from
from typing import Any, Optional, Union

# Used security modules
from Crypto import Hash, Random
from Crypto.Cipher import AES
from Crypto.Hash import CMAC, HMAC
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15

from spsdk import SPSDKError
from spsdk.crypto import PrivateKey

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
        return "SPSDK"

    @property
    def version(self) -> str:
        """Version of the backend."""
        return "0.1"

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
        :raises SPSDKError: If the algorithm is not found
        """
        # algo_cls = getattr(Hash, name.upper(), None)  # hack: get class object by name
        try:
            algo_cls = importlib.import_module(f"Crypto.Hash.{name.upper()}")
        except ModuleNotFoundError as exc:
            raise SPSDKError(f"No module named 'Crypto.Hash.{name.upper()}") from exc
        if algo_cls is None:
            raise SPSDKError(f"Unsupported algorithm: Hash.{name}".format(name=name.upper()))
        return algo_cls.new(data)  # type: ignore  # pylint: disable=not-callable

    def cmac(self, data: bytes, key: bytes) -> bytes:  # pylint: disable=no-self-use
        """Generate Cipher-based Message Authentication Code via AES.

        :param data: Data to digest
        :param key: AES Key for CMAC computation
        :return: CMAC bytes
        """
        cipher = CMAC.new(key=key, ciphermod=AES)
        cipher.update(data)
        return cipher.digest()

    def hash(self, data: bytes, algorithm: str = "sha256") -> bytes:
        """Return a HASH from input data with specified algorithm.

        :param data: Input data in bytes
        :param algorithm: Algorithm type for HASH function
        :return: Hash-ed bytes
        :raises SPSDKError: If the algorithm is not found
        """
        return self._get_algorithm(algorithm, data).digest()

    def hmac(self, key: bytes, data: bytes, algorithm: str = "sha256") -> bytes:
        """Return a HMAC from data with specified key and algorithm.

        :param key: The key in bytes format
        :param data: Input data in bytes format
        :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...)
        :return: HMAC bytes
        :raises SPSDKError: If the algorithm is not found
        """
        cls = getattr(Hash, algorithm.upper(), None)
        if cls is None:
            raise SPSDKError("The algorithm is not found")
        hmac_obj = HMAC.new(key, data, cls)
        return hmac_obj.digest()

    # pylint: disable=invalid-name
    def aes_key_wrap(self, kek: bytes, key_to_wrap: bytes) -> bytes:
        """Wraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param key_to_wrap: Plain data
        :return: Wrapped key
        :raises SPSDKError: Invalid length of kek or key_to_wrap
        """
        if len(kek) not in (16, 24, 32):
            raise SPSDKError("The wrapping key must be a valid AES key length")
        if len(key_to_wrap) < 16:
            raise SPSDKError("The key to wrap must be at least 16 bytes")
        if len(key_to_wrap) % 8 != 0:
            raise SPSDKError("The key to wrap must be a multiple of 8 bytes")
        iv = 0xA6A6A6A6A6A6A6A6
        n = len(key_to_wrap) // 8
        r = [b""] + [key_to_wrap[i * 8 : i * 8 + 8] for i in range(0, n)]
        a = iv
        aes = AES.new(kek, AES.MODE_ECB)
        for j in range(6):
            for i in range(1, n + 1):
                b = aes.encrypt(pack(">Q", a) + r[i])
                a = unpack_from(">Q", b[:8])[0] ^ (n * j + i)
                r[i] = b[8:]
        return pack(">Q", a) + b"".join(r[1:])

    # pylint: disable=invalid-name
    def aes_key_unwrap(self, kek: bytes, wrapped_key: bytes) -> bytes:
        """Unwraps a key using a key-encrypting key (KEK).

        :param kek: The key-encrypting key
        :param wrapped_key: Encrypted data
        :return: Un-wrapped key
        :raises SPSDKError: Invalid length of kek or key_to_wrap
        """
        if len(kek) not in (16, 24, 32):
            raise SPSDKError("The wrapping key must be a valid AES key length")
        if len(wrapped_key) < 24:
            raise SPSDKError("Must be at least 24 bytes")
        if len(wrapped_key) % 8 != 0:
            raise SPSDKError("The wrapped key must be a multiple of 8 bytes")
        # default iv
        iv = 0xA6A6A6A6A6A6A6A6
        n = len(wrapped_key) // 8 - 1
        # NOTE: R[0] is never accessed, left in for consistency with RFC indices
        r = [b""] + [wrapped_key[i * 8 : i * 8 + 8] for i in range(1, n + 1)]
        a = unpack_from(">Q", wrapped_key[:8])[0]
        aes = AES.new(kek, AES.MODE_ECB)
        for j in range(5, -1, -1):  # counting down
            for i in range(n, 0, -1):  # (n, n-1, ..., 1)
                b = aes.decrypt(pack(">Q", a ^ (n * j + i)) + r[i])
                a = unpack_from(">Q", b[:8])[0]
                r[i] = b[8:]
        if a != iv:
            raise SPSDKError(f"Integrity Check Failed: {a:016X} (expected {iv:016X})")
        return b"".join(r[1:])

    def aes_cbc_encrypt(
        self, key: bytes, plain_data: bytes, iv_data: Optional[bytes] = None
    ) -> bytes:
        """Encrypt plain data with AES in CBC mode.

        :param key: Key for encryption
        :param plain_data: Data to encrypt
        :param iv_data: Initial vector for encryption, defaults to None
        :return: Encrypted data
        :raises SPSDKError: Incorrect key or initialization vector size
        """
        if len(key) not in AES.key_size:
            raise SPSDKError(
                f"The key must be a valid AES key length: {', '.join([str(k) for k in AES.key_size])}"
            )
        init_vector = iv_data or bytes(AES.block_size)
        if len(init_vector) != AES.block_size:
            raise SPSDKError(f"The initial vector length must be {AES.block_size}")
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=init_vector)
        return cipher.encrypt(plain_data)

    def aes_cbc_decrypt(
        self, key: bytes, encrypted_data: bytes, iv_data: Optional[bytes] = None
    ) -> bytes:
        """Decrypt encrypted data with AES in CBC mode.

        :param key: The key for data decryption
        :param encrypted_data: Input data
        :param iv_data: Initialization vector data
        :raises SPSDKError: Invalid Key or IV
        :return: Decrypted image
        """
        if len(key) not in AES.key_size:
            raise SPSDKError(
                f"The key must be a valid AES key length: {', '.join([str(k) for k in AES.key_size])}"
            )
        init_vector = iv_data or bytes(AES.block_size)
        if len(init_vector) != AES.block_size:
            raise SPSDKError(f"The initial vector length must be {AES.block_size}")
        cipher = AES.new(key, mode=AES.MODE_CBC, iv=init_vector)
        return cipher.decrypt(encrypted_data)

    def aes_ctr_encrypt(self, key: bytes, plain_data: bytes, nonce: bytes) -> bytes:
        """Encrypt plain data with AES in CTR mode.

        :param key: The key for data encryption
        :param plain_data: Input data
        :param nonce: Nonce data with counter value
        :return: Encrypted data
        :raises SPSDKError: Invalid length of key
        :raises SPSDKError: Invalid length of nonce
        :raises SPSDKError: Invalid length of plain text
        """
        if len(key) not in (16, 24, 32):
            raise SPSDKError("The key must be a valid AES key length")
        if len(nonce) != 16:
            raise SPSDKError("The nonce length is not valid")
        if len(plain_data) > len(nonce):
            raise SPSDKError("The length of plain text is large than the length of nonce")
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

    def aes_xts_encrypt(self, key: bytes, plain_data: bytes, tweak: bytes) -> bytes:
        """Encrypt plain data with AES in XTS mode.

        :param key: The key for data encryption
        :param plain_data: Input data
        :param tweak: The tweak is a 16 byte value
        :return: Encrypted data
        :raises NotImplementedError: This backend doesn't support AES-XTS
        """
        raise NotImplementedError("This backend doesn't support AES-XTS")

    def aes_xts_decrypt(self, key: bytes, encrypted_data: bytes, tweak: bytes) -> bytes:
        """Decrypt encrypted data with AES in XTS mode.

        :param key: The key for data decryption
        :param encrypted_data: Input data
        :param tweak: The tweak is a 16 byte value
        :return: Decrypted data
        :raises NotImplementedError: This backend doesn't support AES-XTS
        """
        raise NotImplementedError("This backend doesn't support AES-XTS")

    def rsa_sign(
        self,
        private_key: Union[RSA.RsaKey, bytes],
        data: bytes,
        algorithm: str = "sha256",
    ) -> bytes:
        """Sign input data.

        :param private_key: The private key: either RSA.RsaKey or decrypted binary data in PEM format
        :param data: Input data
        :param algorithm: Used algorithm
        :return: Singed data
        :raises SPSDKError: If the algorithm is not found
        """
        if isinstance(private_key, bytes):
            private_key = RSA.import_key(private_key)
        assert isinstance(private_key, RSA.RsaKey)
        h = self._get_algorithm(algorithm, data)
        return pkcs1_15.new(private_key).sign(h)

    def rsa_verify(
        self,
        pub_key_mod: int,
        pub_key_exp: int,
        signature: bytes,
        data: bytes,
        algorithm: str = "sha256",
    ) -> bool:
        """Verify input data.

        :param pub_key_mod: The public key modulus
        :param pub_key_exp: The public key exponent
        :param signature: The signature of input data
        :param data: Input data
        :param algorithm: Used algorithm
        :return: True if signature is valid, False otherwise
        :raises SPSDKError: If the algorithm is not found
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

    def ecc_sign(
        self, private_key: Union[ECC.EccKey, bytes], data: bytes, algorithm: Optional[str] = None
    ) -> bytes:
        """Sign data using (EC)DSA.

        :param private_key: ECC private key, either as EccKey or bytes
        :param data: Data to sign
        :param algorithm: Hash algorithm, if None the hash length is determined from ECC curve size
        :return: Signature, r and s coordinates as bytes
        """
        key = private_key if isinstance(private_key, ECC.EccKey) else ECC.import_key(private_key)
        hash_name = algorithm or f"sha{key.pointQ.size_in_bits()}"
        hasher = self._get_algorithm(name=hash_name, data=data)
        signer = DSS.new(key, mode="deterministic-rfc6979")
        return signer.sign(hasher)

    def ecc_verify(
        self,
        key: Union[ECC.EccKey, bytes],  # TODO  - could we renamed abstract class to "key" only?
        signature: bytes,
        data: bytes,
        algorithm: Optional[str] = None,
    ) -> bool:
        """Verify (EC)DSA signature.

        :param key: ECC private or public key, either as EccKey or bytes
        :param signature: Signature to verify, r and s coordinates as bytes
        :param data: Data to validate
        :param algorithm: Hash algorithm, if None the hash length is determined from ECC curve size
        :return: True if the signature is valid
        :raises SPSDKError: Signature length is invalid
        """
        key = key if isinstance(key, ECC.EccKey) else ECC.import_key(key)
        hash_name = algorithm or f"sha{key.pointQ.size_in_bits()}"
        coordinate_size = key.pointQ.size_in_bytes()
        if len(signature) != 2 * coordinate_size:
            raise SPSDKError(
                f"Invalid signature size: expected {2 * coordinate_size}, actual: {len(signature)}"
            )
        hasher = self._get_algorithm(name=hash_name, data=data)
        try:
            DSS.new(key, mode="deterministic-rfc6979").verify(hasher, signature)
            return True
        except ValueError:
            return False

    @staticmethod
    def sign_size(key: PrivateKey) -> int:
        """Get size of signature for loaded private key.

        :param key: Private key used to sign data.
        :return: Size of signature in bytes for the private key.
        :raises SPSDKError: Invalid key type.
        """
        if isinstance(key, ECC.EccKey):
            return math.ceil(key.key_size / 8) * 2

        if isinstance(key, RSA.RsaKey):
            return key.key_size // 8

        raise SPSDKError(f"Unsupported private key type to get signature size. {type(key)}")


########################################################################################################################
# SPSDK Backend instance
########################################################################################################################
internal_backend = Backend()  # pylint: disable=invalid-name
