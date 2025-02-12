#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""OpenSSL implementation for HKDF key derivation."""

from cryptography.hazmat.primitives.hashes import SHA256

# Used security modules
from cryptography.hazmat.primitives.kdf import hkdf as hkdf_cls


def hkdf(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """Return a derived key by HKDF algorithm from IKM with specified salt and info.

    :param salt: The randomize material.
    :param ikm: Input Key Material
    :param info: Additional input info material
    :param length: Final key length
    :return: Derived key
    """
    hkdf_obj = hkdf_cls.HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return hkdf_obj.derive(ikm)
