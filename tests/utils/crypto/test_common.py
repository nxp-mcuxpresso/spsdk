#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
""" Test of common crypto utilities module."""


import pytest
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1

from spsdk import SPSDKError
from spsdk.utils.crypto import Counter
from spsdk.utils.crypto.common import EllipticCurvePublicNumbers, ecc_public_numbers_to_bytes


def test_counter():
    """Test of Counter."""
    # simple counter with nonce only
    cntr = Counter(bytes([0] * 16))
    assert cntr.value == bytes([0] * 16)

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567, ctr_byteorder_encoding="little")
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as little endian
    cntr = Counter(bytes([0] * 16), ctr_value=0x01234567)
    assert cntr.value == bytes([0] * 12 + [0x67, 0x45, 0x23, 0x01])

    # counter with nonce and counter encoded as big endian
    cntr = Counter(bytes([0] * 16), ctr_value=1, ctr_byteorder_encoding="big")
    assert cntr.value == bytes([0] * 15 + [1])

    # increment
    cntr.increment()
    assert cntr.value == bytes([0] * 15 + [2])
    cntr.increment(2)
    assert cntr.value == bytes([0] * 15 + [4])
    cntr.increment(256)
    assert cntr.value == bytes([0] * 14 + [1, 4])


def test_counter_invalid():
    with pytest.raises(SPSDKError, match="Wrong byte order"):
        Counter(nonce=bytes(16), ctr_byteorder_encoding="BIG")


def test_ecc_public_numbers_to_bytes():
    """Test conversion ECC public numbers to bytes."""
    ecc = EllipticCurvePublicNumbers(0x1234567890ABCDEF, 0xEFCDAB9078563412, SECP256R1())
    assert (
        ecc_public_numbers_to_bytes(ecc)
        == b"\x12\x34\x56\x78\x90\xab\xcd\xef\xef\xcd\xab\x90\x78\x56\x34\x12"
    )
    assert (
        ecc_public_numbers_to_bytes(ecc, 8)
        == b"\x12\x34\x56\x78\x90\xab\xcd\xef\xef\xcd\xab\x90\x78\x56\x34\x12"
    )
