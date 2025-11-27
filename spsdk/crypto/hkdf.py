#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HKDF key derivation utilities.

This module provides HMAC-based Key Derivation Function (HKDF) implementation
for secure key derivation operations in SPSDK applications.
"""

from cryptography.hazmat.primitives.hashes import SHA256

# Used security modules
from cryptography.hazmat.primitives.kdf import hkdf as hkdf_cls


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Derive key using HKDF (HMAC-based Key Derivation Function) algorithm.

    The function implements RFC 5869 HKDF algorithm to derive cryptographic keys from
    input key material using salt and additional context information.

    :param salt: Salt value used as randomization material for key derivation.
    :param ikm: Input Key Material - the source cryptographic material.
    :param info: Additional context information for key derivation.
    :param length: Length of the derived key in bytes.
    :return: Derived cryptographic key as bytes.
    """
    hkdf_obj = hkdf_cls.HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return hkdf_obj.derive(ikm)
