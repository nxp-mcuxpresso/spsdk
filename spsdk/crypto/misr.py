#!/usr/bin/env python
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


def calculate_misr_checksum(
    misr_seed: bytes,
    data: bytes,
    data_alignment: int = 128,
    seed_byte_order: str = "little",
) -> bytes:
    """Calculate MISR checksum over multiple data blocks.

    :param misr_seed: Initial 16-byte bytes object MISR seed value
    :param data: Data to calculate MISR checksum over
    :param data_alignment: Required input-data alignment in bytes, defaults to 128
    :param seed_byte_order: Byte order used to interpret the MISR seed, defaults to little
    :returns: Final 16-byte bytes object MISR checksum
    """
    if len(misr_seed) != 16:
        raise SPSDKError("MISR seed must be 16 bytes")

    if data_alignment <= 0 or data_alignment % 16:
        raise SPSDKError("MISR data alignment must be a positive multiple of 16 bytes")

    if seed_byte_order == "big":
        cur_misr = int.from_bytes(misr_seed, byteorder="big")
    elif seed_byte_order == "little":
        cur_misr = int.from_bytes(misr_seed, byteorder="little")
    else:
        raise SPSDKError("MISR seed byte order must be either 'big' or 'little'")

    if len(data) % data_alignment != 0:
        raise SPSDKError(f"Data length must be a multiple of {data_alignment} bytes")

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
