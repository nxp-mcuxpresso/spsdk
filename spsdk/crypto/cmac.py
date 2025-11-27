#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2019-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK CMAC (Cipher-based Message Authentication Code) implementation.

This module provides cryptographic functions for generating and validating
CMAC authentication codes using AES encryption for secure packet authentication
in SPSDK applications.
"""

# Used security modules
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import cmac as cmac_cls
from cryptography.hazmat.primitives.ciphers import algorithms


def cmac(key: bytes, data: bytes) -> bytes:
    """Compute CMAC (Cipher-based Message Authentication Code) for given data.

    Uses AES algorithm to generate a cryptographic message authentication code
    that provides both data integrity and authenticity verification.

    :param key: AES encryption key in bytes format
    :param data: Input data to be authenticated in bytes format
    :return: CMAC authentication code as bytes
    """
    cmac_obj = cmac_cls.CMAC(algorithm=algorithms.AES(key))
    cmac_obj.update(data)
    return cmac_obj.finalize()


def cmac_validate(key: bytes, data: bytes, signature: bytes) -> bool:
    """Validate CMAC signature against provided data using specified key.

    The method uses AES algorithm to compute CMAC and verifies it against the provided
    signature.

    :param key: The key in bytes format for CMAC computation
    :param data: Input data in bytes format to be validated
    :param signature: CMAC signature in bytes format to validate against
    :raises InvalidSignature: When signature validation fails
    :return: True if signature is valid, False otherwise
    """
    cmac_obj = cmac_cls.CMAC(algorithm=algorithms.AES(key))
    cmac_obj.update(data)
    try:
        cmac_obj.verify(signature=signature)
        return True
    except InvalidSignature:
        return False
