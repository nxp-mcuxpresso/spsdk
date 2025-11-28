#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HMAC authentication utilities.

This module provides HMAC (Hash-based Message Authentication Code) functionality
for packet authentication and validation using cryptographic hash algorithms.
"""

from cryptography.exceptions import InvalidSignature

# Used security modules
from cryptography.hazmat.primitives import hmac as hmac_cls

from spsdk.crypto.hash import EnumHashAlgorithm, get_hash_algorithm


def hmac(key: bytes, data: bytes, algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256) -> bytes:
    """Compute HMAC from data with specified key and algorithm.

    The method generates Hash-based Message Authentication Code using the provided
    key, data, and hash algorithm. Supports various hash algorithms including SHA256,
    SHA384, and SHA512.

    :param key: The cryptographic key in bytes format.
    :param data: Input data to be authenticated in bytes format.
    :param algorithm: Hash algorithm type for HMAC computation, defaults to SHA256.
    :return: HMAC digest as bytes.
    """
    hmac_obj = hmac_cls.HMAC(key, get_hash_algorithm(algorithm))
    hmac_obj.update(data)
    return hmac_obj.finalize()


def hmac_validate(
    key: bytes,
    data: bytes,
    signature: bytes,
    algorithm: EnumHashAlgorithm = EnumHashAlgorithm.SHA256,
) -> bool:
    """Validate HMAC signature against provided data using specified key and algorithm.

    :param key: The key in bytes format used for HMAC generation.
    :param data: Input data in bytes format to validate against signature.
    :param signature: HMAC signature in bytes format to validate.
    :param algorithm: Algorithm type for HASH function (sha256, sha384, sha512, ...).
    :return: True if signature is valid, False otherwise.
    """
    hmac_obj = hmac_cls.HMAC(key=key, algorithm=get_hash_algorithm(algorithm))
    hmac_obj.update(data)
    try:
        hmac_obj.verify(signature=signature)
        return True
    except InvalidSignature:
        return False
