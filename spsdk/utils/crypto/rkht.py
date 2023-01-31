#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""The module provides support for Root Key Hash table."""

import logging
import math
from typing import List, Optional, Union

from spsdk.crypto import (
    Certificate,
    EllipticCurvePublicKey,
    PrivateKey,
    PublicKey,
    RSAPublicKey,
    _PrivateKeyTuple,
    _PublicKeyTuple,
)
from spsdk.crypto.loaders import extract_public_key, extract_public_key_from_data
from spsdk.exceptions import SPSDKError
from spsdk.utils.crypto.common import crypto_backend

logger = logging.getLogger(__name__)


class RKHT:
    """Root Key Hash Table class."""

    def __init__(
        self,
        keys: Optional[List] = None,
        keys_cnt: int = 4,
        min_keys_cnt: int = 4,
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> None:
        """Initialization of Root Key Hash Table class.

        :param keys: List of source of root keys (The public keys could get also from private key
            or certificates), defaults to None
        :param password: Optional password to open secured private keys, defaults to None.
        :param search_paths: List of paths where to search for the file, defaults to None
        """
        self.keys_cnt = keys_cnt
        self.min_keys_cnt = min_keys_cnt
        self.rotk = (
            [RKHT.convert_key(x, password, search_paths=search_paths) for x in keys] if keys else []
        )

    @staticmethod
    def _hash_algorithm_output_size(key: PublicKey) -> int:
        """Get Hash algorithm output size for the key.

        :param key: Key to get hash.
        :raises SPSDKError: Invalid kye type.
        :return: Size in bits of hash.
        """
        if isinstance(key, EllipticCurvePublicKey):
            return key.key_size

        if isinstance(key, RSAPublicKey):
            # In case of RSA keys, hash is always SHA-256, regardless of the key length
            return 256

        raise SPSDKError("RKHT: Unsupported key type to load.")

    @staticmethod
    def _hash_algorithm(key: PublicKey) -> str:
        """Get Hash algorithm name for the key.

        :param key: Key to get hash.
        :raises SPSDKError: Invalid kye type.
        :return: Name of hash algorithm.
        """
        return f"sha{RKHT._hash_algorithm_output_size(key)}"

    @property
    def hash_algorithm(self) -> str:
        """Used HASH algorithm name."""
        assert len(self.rotk) > 0
        return RKHT._hash_algorithm(self.rotk[0])

    @property
    def hash_algorithm_size(self) -> int:
        """Used HASH algorithm size in bytes."""
        assert len(self.rotk) > 0
        return RKHT._hash_algorithm_output_size(self.rotk[0])

    def validate(self) -> None:
        """Validate the RKHT object."""
        if len(self.rotk) == 0:
            raise SPSDKError("RKHT is missing input public keys.")

        if self.keys_cnt >= len(self.rotk) < self.min_keys_cnt:
            raise SPSDKError(f"RKHT: Invalid key count: ({len(self.rotk)}).")

        if not all(isinstance(x, type(self.rotk[0])) for x in self.rotk):
            raise SPSDKError("RKHT must contains all keys same instances.")
        if not all(RKHT._hash_algorithm(x) == self.hash_algorithm for x in self.rotk):
            raise SPSDKError("RKHT must have same hash algorithm for all keys.")

    @staticmethod
    def calc_key_hash(
        public_key: PublicKey,
        sha_width: int = 256,
    ) -> bytes:
        """Calculate a hash out of public key's exponent and modulus in RSA case, X/Y in EC.

        :param public_key: List of public keys to compute hash from.
        :param sha_width: Used hash algorithm.
        :raises SPSDKError: Unsupported public key type
        :return: Computed hash.
        """
        if isinstance(public_key, RSAPublicKey):
            n_1: int = public_key.public_numbers().e  # type: ignore # MyPy is unable to pickup the class member
            n1_len = math.ceil(n_1.bit_length() / 8)
            n_2: int = public_key.public_numbers().n  # type: ignore # MyPy is unable to pickup the class member
            n2_len = math.ceil(n_2.bit_length() / 8)
        elif isinstance(public_key, EllipticCurvePublicKey):
            n_1: int = public_key.public_numbers().y  # type: ignore # MyPy is unable to pickup the class member
            n1_len = sha_width // 8
            n_2: int = public_key.public_numbers().x  # type: ignore # MyPy is unable to pickup the class member
            n2_len = sha_width // 8
        else:
            raise SPSDKError(f"Unsupported key type: {type(public_key)}")

        n1_bytes = n_1.to_bytes(n1_len, "big")
        n2_bytes = n_2.to_bytes(n2_len, "big")

        return crypto_backend().hash(n2_bytes + n1_bytes, algorithm=f"sha{sha_width}")

    def key_hashes(self) -> List[bytes]:
        """List of individual key hashes.

        :return: List of individual key hashes.
        """
        ret = []
        for i in range(self.keys_cnt):
            if i < len(self.rotk) and self.rotk[i]:
                ret.append(
                    RKHT.calc_key_hash(self.rotk[i], RKHT._hash_algorithm_output_size(self.rotk[i]))
                )
            else:
                ret.append(bytes(RKHT._hash_algorithm_output_size(self.rotk[0]) // 8))
        return ret

    def rotkh(self) -> bytes:
        """Root of Key Table hash.

        :return: Hash of Hashes of public key.
        """
        rotkh = crypto_backend().hash(bytearray().join(self.key_hashes()), self.hash_algorithm)
        logger.info(f"ROTKH: {rotkh.hex()}")
        return rotkh

    def add_key(self, key: PublicKey) -> None:
        """Add additional public key.

        :param key: Root of Trust public key.
        """
        self.rotk.append(key)

    @staticmethod
    def convert_key(
        key: Union[str, bytes, bytearray, PublicKey, PrivateKey, Certificate],
        password: Optional[str] = None,
        search_paths: Optional[List[str]] = None,
    ) -> PublicKey:
        """Convert practically whole input that could hold Public key into public key.

        :param key: Public key in Certificate/Private key, Public key as a path to file,
            loaded bytes or supported class.
        :param password: Optional password to open secured private keys, defaults to None.
        :param search_paths: List of paths where to search for the file, defaults to None
        :raises SPSDKError: Invalid kye type.
        :return: Public Key object.
        """
        if isinstance(key, _PublicKeyTuple):
            return key

        if isinstance(key, _PrivateKeyTuple):
            return key.public_key()

        if isinstance(key, Certificate):
            public_key = key.public_key()
            assert isinstance(public_key, _PublicKeyTuple)
            return public_key

        if isinstance(key, str):
            return extract_public_key(key, password, search_paths=search_paths)

        if isinstance(key, (bytes, bytearray)):
            return extract_public_key_from_data(key, password)

        raise SPSDKError("RKHT: Unsupported key to load.")
