#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Test of bit array module."""
from bitstring import BitArray


def test_basic():
    """Test of BitArray - Basic test."""
    bit_array = BitArray(f"uint:32={0x1111}")
    assert len(bit_array) == 32
    bit_low = bit_array[16:]
    assert len(bit_low) == 16
    assert bit_low.hex == "1111"


def test_invert():
    """Test of BitArray - Invert."""
    bit_array = BitArray(f"uint:32={0x1111}")
    bit_low = bit_array[16:]
    bit_low.invert()
    assert bit_low.hex == "eeee"
    bit_array.overwrite(bit_low, 0)
    assert bit_array.hex == "eeee1111"


def test_byteswap():
    """Test of BitArray - Byte swap."""
    bit_array = BitArray(f"uint:32={0x1234_5678}")
    bit_array.byteswap()
    assert bit_array.hex == "78563412"
