#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK Miyaguchi-Preneel hash function tests.

This module contains unit tests for the Miyaguchi-Preneel hash function
implementation used in SPSDK cryptographic operations.
"""

from spsdk.crypto.miyaguchi_preneel import mp_compress, mp_padding


def test_mp_padding() -> None:
    """Test Miyaguchi-Preneel padding function with known test vector.

    Verifies that the mp_padding function correctly generates padding bytes
    for a given input data by comparing against expected padding values.
    The test ensures both length and content correctness of the padding.
    """
    data = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    exp_padding = bytes.fromhex("80000000000000000000000000000100")

    padding = mp_padding(data=data)

    assert len(padding) == len(exp_padding)
    assert padding == exp_padding


def test_mp_compress() -> None:
    """Test Miyaguchi-Preneel compression function with known test vector.

    Verifies that the mp_compress function correctly compresses the input data
    and produces the expected output by comparing against a known test vector.
    The test ensures both the length and content of the compressed output match
    the expected values.
    """
    data = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    exp_compress = bytes.fromhex("c7277a0dc1fb853b5f4d9cbd26be40c6")

    compress = mp_compress(data=data)

    assert len(compress) == len(exp_compress)
    assert compress == exp_compress
