#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK PFR bitarray functionality.

This module contains unit tests for bit array operations used in the
Protected Flash Region (PFR) context within SPSDK, ensuring proper
handling of bit-level data manipulation and transformations.
"""

from bitstring import BitArray


def test_basic() -> None:
    """Test basic functionality of BitArray class.

    Verifies BitArray initialization with hexadecimal value, length calculation,
    slicing operations, and hexadecimal representation of sliced segments.

    :raises AssertionError: If any of the BitArray operations don't produce expected results.
    """
    bit_array = BitArray(f"uint:32={0x1111}")
    assert len(bit_array) == 32
    bit_low = bit_array[16:]
    assert len(bit_low) == 16
    assert bit_low.hex == "1111"


def test_invert() -> None:
    """Test BitArray invert functionality.

    Verifies that the invert operation correctly flips all bits in a BitArray slice
    and that the modified slice can be written back to the original array.

    :raises AssertionError: If the invert operation doesn't produce expected results.
    """
    bit_array = BitArray(f"uint:32={0x1111}")
    bit_low = bit_array[16:]
    bit_low.invert()
    assert bit_low.hex == "eeee"
    bit_array.overwrite(bit_low, 0)
    assert bit_array.hex == "eeee1111"


def test_byteswap() -> None:
    """Test byte swap functionality of BitArray class.

    Verifies that the byteswap method correctly reverses the byte order
    of a 32-bit integer value from big-endian to little-endian format.
    """
    bit_array = BitArray(f"uint:32={0x1234_5678}")
    bit_array.byteswap()
    assert bit_array.hex == "78563412"
