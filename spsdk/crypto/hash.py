#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic hash algorithms implementation.

This module provides a unified interface for various hash algorithms used across
SPSDK, including SHA-1, SHA-224, SHA-256, SHA-384, and SHA-512. It offers
enumeration of supported algorithms, hash computation utilities, and algorithm
metadata retrieval functions.
"""

# Used security modules

from math import ceil

from cryptography.hazmat.primitives import hashes

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import Endianness
from spsdk.utils.spsdk_enum import SpsdkEnum


class EnumHashAlgorithm(SpsdkEnum):
    """Hash algorithm enumeration for cryptographic operations.

    This enumeration defines supported hash algorithms used across SPSDK for
    cryptographic operations including signing, verification, and data integrity
    checks. Each algorithm is represented with its numeric identifier, string
    representation, and display name.
    """

    SHA1 = (0, "sha1", "SHA1")
    SHA256 = (1, "sha256", "SHA256")
    SHA384 = (2, "sha384", "SHA384")
    SHA512 = (3, "sha512", "SHA512")
    MD5 = (4, "md5", "MD5")
    SM3 = (5, "sm3", "SM3")
    SHA3_256 = (6, "sha3_256", "SHA3_256")
    SHA3_384 = (7, "sha3_384", "SHA3_384")
    SHA3_512 = (8, "sha3_512", "SHA3_512")
    SHAKE_128_256 = (9, "shake_128_256", "SHAKE128 with 256b output")
    SHAKE_256_512 = (10, "shake_256_512", "SHAKE256 with 512b output")
    NONE = (254, "none", "NONE")


def get_hash_algorithm(algorithm: EnumHashAlgorithm) -> hashes.HashAlgorithm:
    """Get hash algorithm instance for specified algorithm type.

    The method handles special cases for SHAKE algorithms with predefined digest sizes
    and uses dynamic class lookup for standard hash algorithms.

    :param algorithm: Hash algorithm type enumeration value.
    :raises SPSDKError: If the specified algorithm is not supported.
    :return: Instance of the corresponding hash algorithm class.
    """
    cls_name = algorithm.label.upper()
    if cls_name in ["SHAKE_128_256", "SHAKE128"]:
        return hashes.SHAKE128(digest_size=32)
    if cls_name in ["SHAKE_256_512", "SHAKE256"]:
        return hashes.SHAKE256(digest_size=64)

    algo_cls = getattr(hashes, cls_name, None)  # hack: get class object by name
    if algo_cls is None:
        raise SPSDKError(f"Unsupported algorithm: hashes.{cls_name}")
    return algo_cls()  # pylint: disable=not-callable


def get_hash_length(algorithm: EnumHashAlgorithm) -> int:
    """Get hash algorithm binary length.

    Returns the digest size in bytes for the specified hash algorithm.

    :param algorithm: Hash algorithm type enumeration.
    :return: Length of hash digest in bytes.
    :raises SPSDKError: If algorithm is not supported or found.
    """
    return get_hash_algorithm(algorithm).digest_size


class Hash:
    """SPSDK Hash computation wrapper.

    This class provides a unified interface for cryptographic hash operations
    across different hash algorithms. It wraps the underlying cryptographic
    library to offer consistent hash computation functionality with support
    for incremental data processing and various data types.
    """

    def __init__(self, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> None:
        """Initialize hash object.

        :param algorithm: Algorithm type enum, defaults to EnumHashAlgorithm.SHA256
        """
        self.hash_obj = hashes.Hash(get_hash_algorithm(algorithm))

    def update(self, data: bytes) -> None:
        """Update the hash object with new data.

        :param data: Binary data to be added to the hash calculation.
        """
        self.hash_obj.update(data)

    def update_int(self, value: int) -> None:
        """Update the hash by new integer value as is.

        The method converts the absolute value of the integer to bytes using big-endian
        byte order and updates the hash with the resulting byte data.

        :param value: Integer value to be hashed (absolute value will be used).
        """
        value = abs(value)
        data = value.to_bytes(length=ceil(value.bit_length() / 8), byteorder=Endianness.BIG.value)
        self.update(data)

    def finalize(self) -> bytes:
        """Finalize the hash computation and return the digest.

        This method completes the hash computation process and returns the final hash digest.
        After calling this method, the hash object cannot be used for further updates.

        :return: The computed hash digest as bytes.
        """
        return self.hash_obj.finalize()


def get_hash(data: bytes, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
    """Compute hash digest from input data using specified algorithm.

    :param data: Input data to be hashed.
    :param algorithm: Hash algorithm to use for computation.
    :raises SPSDKError: If the specified algorithm is not supported.
    :return: Hash digest as bytes.
    """
    hash_obj = hashes.Hash(get_hash_algorithm(algorithm))
    hash_obj.update(data)
    return hash_obj.finalize()
