#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""MISR (Multiple Input Signature Register) implementation for cryptographic operations."""

from spsdk.exceptions import SPSDKError


def _misr_128(misr: int, data: bytes) -> int:
    """MISR-128: takes 128 bits of data and returns 128 bit MISR.

    Polynomial: X^128 + X^126 + X^101 + X^99 + 1

    :param misr_start: 16-byte bytes object representing the current MISR state
    :param data: 16-byte bytes object representing the input data
    :returns: 16-byte bytes object representing the new MISR state
    """
    data_int = int.from_bytes(data, byteorder="little")

    # Get the MSB (bit 127)
    bit_128 = (misr >> 127) & 1

    # Shift the MISR left by 1 and OR in bit_128
    misr_result = ((misr << 1) | bit_128) & ((1 << 128) - 1)

    # Polynomial: X128 + X126 + X101 + X99 + 1
    # polynomial = (1 << 126) | (1 << 101) | (1 << 99)

    for ii in [126, 101, 99]:
        if bit_128:
            misr_result ^= 1 << ii

    misr_result ^= data_int
    misr_result = misr_result & ((1 << 128) - 1)
    return misr_result


def calculate_misr_checksum(misr_seed: bytes, data: bytes) -> bytes:
    """Calculate MISR checksum over multiple data blocks.

    :param misr_seed: Initial 16-byte bytes object MISR seed value
    :param data: Data to calculate MISR checksum over
    :returns: Final 16-byte bytes object MISR checksum
    """
    if len(misr_seed) != 16:
        raise SPSDKError("MISR seed must be 16 bytes")

    if len(data) % 128 != 0:
        raise SPSDKError("Data length must be a multiple of 128 bytes")

    cur_misr = int.from_bytes(misr_seed, byteorder="little")

    data_blocks = [data[i : i + 16] for i in range(0, len(data), 16)]

    for data_block in data_blocks:
        cur_misr = _misr_128(cur_misr, data_block)
    return cur_misr.to_bytes(16, byteorder="little")


def add_misr_padding(data: bytes) -> bytes:
    """Add MISR padding to data.

    :param data: Data to pad
    :returns: Padded data
    """
    padded_length = ((len(data) + 127) // 128) * 128
    return data.ljust(padded_length, b"\xff")
