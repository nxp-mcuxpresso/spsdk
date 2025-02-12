#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""LPCProg utility functions."""

import struct

CRP_OFFSET = 0x2FC
CRP_LENGTH = 4
CHECKSUM_VECTOR_TABLE_OFFSET = 0x1C
VECT_TABLE_SIZE = 32


def lpcprog_update_crp_value(bin_data: bytes, crp: int) -> bytes:
    """Update the CRP value in a binary image.

    :param bin_data: The original binary data.
    :param crp: The CRP value to be set.
    :return: The modified binary data with the updated CRP value.
    """
    if len(bin_data) < CRP_OFFSET + CRP_LENGTH:
        raise ValueError("Binary data is too short to contain a CRP value at the specified offset.")

    # Convert the CRP value to bytes
    crp_bytes = crp.to_bytes(CRP_LENGTH, byteorder="little")

    # Update the CRP value in the binary data
    updated_bin_data = bin_data[:CRP_OFFSET] + crp_bytes + bin_data[CRP_OFFSET + CRP_LENGTH :]

    return updated_bin_data


def lpcprog_make_image_bootable(data: bytes) -> bytes:
    """Make the image bootable by inserting the checksum in the correct place.

    :param data: image data
    :return: image data with correct checksum
    """
    if len(data) < VECT_TABLE_SIZE:
        raise ValueError("Binary data is too short to contain a valid vector table.")

    # Calculate the checksum of the first 7 entries
    checksum = sum(struct.unpack("<7I", data[:CHECKSUM_VECTOR_TABLE_OFFSET])) & 0xFFFFFFFF

    # Calculate the 2's complement of the checksum
    checksum = (~checksum + 1) & 0xFFFFFFFF

    # Insert the checksum at the 8th entry (offset 0x1C)
    bootable_data = (
        data[:CHECKSUM_VECTOR_TABLE_OFFSET]
        + struct.pack("<I", checksum)
        + data[CHECKSUM_VECTOR_TABLE_OFFSET + 4 :]
    )

    return bootable_data
