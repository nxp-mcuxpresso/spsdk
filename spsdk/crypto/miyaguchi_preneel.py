#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module with helper functions for Miyaguchi-Preneel hash function implementation."""

import functools
import operator

from bitstring import Bits

from spsdk.crypto.symmetric import aes_ecb_encrypt
from spsdk.exceptions import SPSDKError

DATA_BYTE_ALIGNMENT = 16
DATA_BIT_ALIGNMENT = DATA_BYTE_ALIGNMENT * 8


def xor_bytes(*data: bytes) -> bytes:
    """Perform byte-by-byte XOR on bytes."""
    if not all(len(d) == len(data[0]) for d in data):
        raise SPSDKError("All bytes object must be of the same length.")
    return bytes(functools.reduce(operator.xor, t) for t in zip(*data))


def mp_padding(data: bytes) -> bytes:
    """Calculate padding."""
    l = len(data) * 8  # noqa: E741  # we want to use naming consistent with spec
    k = (88 - l - 1) % DATA_BIT_ALIGNMENT
    if (l + 1 + k) % DATA_BIT_ALIGNMENT != 88:
        raise SPSDKError("Padding calculation malfunctioned")
    padding = Bits("0b1") + Bits(k) + Bits(uint=l, length=40)
    return padding.tobytes()


def mp_compress(data: bytes) -> bytes:
    """Compress data."""
    data += mp_padding(data=data)
    if len(data) % DATA_BYTE_ALIGNMENT != 0:
        raise SPSDKError(f"Data length must be divisible by {DATA_BYTE_ALIGNMENT}. Got {len(data)}")

    prev = bytes(DATA_BYTE_ALIGNMENT)
    for offset in range(0, len(data), DATA_BYTE_ALIGNMENT):
        chunk = data[offset : offset + DATA_BYTE_ALIGNMENT]
        enc = aes_ecb_encrypt(key=prev, plain_data=chunk)
        prev = xor_bytes(enc, chunk, prev)
    return prev
