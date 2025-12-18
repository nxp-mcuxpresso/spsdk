#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Common definitions and enumerations for HSE (Hardware Security Engine) key operations.

This module provides common types and enumerations used across HSE key management..
"""

from enum import IntEnum

from spsdk.utils.spsdk_enum import SpsdkEnum


class HseKeyBits(IntEnum):
    """HSE Key Bits.

    Some default key bits values.
    """

    INVALID = 0xFFFF
    ZERO = 0
    KEY64_BITS = 64
    KEY128_BITS = 128
    KEY160_BITS = 160
    KEY192_BITS = 192
    KEY224_BITS = 224
    KEY240_BITS = 240
    KEY256_BITS = 256
    KEY320_BITS = 320
    KEY384_BITS = 384
    KEY512_BITS = 512
    KEY521_BITS = 521
    KEY638_BITS = 638
    KEY1024_BITS = 1024
    KEY2048_BITS = 2048
    KEY3072_BITS = 3072
    KEY4096_BITS = 4096


class KeyType(SpsdkEnum):
    """Enumeration of HSE key types.

    Defines the available key types that can be used with HSE key operations.
    """

    SHE = (0x11, "SHE", "SHE key")
    AES = (0x12, "AES", "AES key")
    HMAC = (0x20, "HMAC", "HMAC key")
    SHARED_SECRET = (0x30, "SHARED_SECRET", "Shared secret key")
    SIPHASH = (0x40, "SIPHASH", "SipHash key")
    ECC_PAIR = (0x87, "ECC_PAIR", "ECC key pair")
    ECC_PUB = (0x88, "ECC_PUB", "ECC public key")
    ECC_PUB_EXT = (0x89, "ECC_PUB_EXT", "ECC public key external")
    RSA_PAIR = (0x97, "RSA_PAIR", "RSA key pair")
    RSA_PUB = (0x98, "RSA_PUB", "RSA public key")
    RSA_PUB_EXT = (0x99, "RSA_PUB_EXT", "RSA public key external")
    DH_PAIR = (0xA7, "DH_PAIR", "Diffie-Hellman key pair")
    DH_PUB = (0xA8, "DH_PUB", "Diffie-Hellman public key")
