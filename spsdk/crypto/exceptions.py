#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK cryptographic exceptions module.

This module defines custom exception classes for handling cryptographic
errors within the SPSDK framework, providing specific error types for
crypto operations and key validation failures.
"""

from spsdk.exceptions import SPSDKError


class SPSDKPCryptoError(SPSDKError):
    """General SPSDK Crypto Error.

    Base exception class for all cryptographic operations within SPSDK.
    This exception is raised when cryptographic operations fail, including
    key generation, encryption, decryption, signing, and verification errors.
    """


class SPSDKKeysNotMatchingError(SPSDKPCryptoError):
    """SPSDK cryptographic key mismatch exception.

    This exception is raised when cryptographic key pairs do not match during
    validation or verification operations in SPSDK cryptographic functions.
    """
