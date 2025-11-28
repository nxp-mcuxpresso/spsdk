#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK WIC (Wic Image Creator) file manipulation utilities.

This module provides functionality for working with WIC image files, including
U-Boot bootloader detection, replacement, and tag generation for proper image
handling in SPSDK workflows.
"""

import logging
import os
import re

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import align_block, load_binary

logger = logging.getLogger(__name__)

# cspell:ignore UUUBURNXXOEUZX7 A-XY5601QQWWZ

UBOOT_END_PATTERN = rb"UUUBURNXXOEUZX7\+A-XY5601QQWWZ(\d+)(END)"
UBOOT_OFFSET = 0x8000
READ_LIMIT = 0x800000


def generate_tag(end_address: int) -> bytes:
    """Generate a tag with the provided end address.

    The method creates a formatted tag string containing a fixed prefix pattern
    and the specified end address, then encodes it to ASCII bytes.

    :param end_address: The end address to be included in the tag.
    :return: The tag as a byte string.
    """
    return f"UUUBURNXXOEUZX7+A-XY5601QQWWZ{end_address}END".encode("ascii")


def match_uboot_tag(binary_data: bytes, pattern: bytes = UBOOT_END_PATTERN) -> int:
    """Match U-Boot end tag in WIC file.

    This method searches for a U-Boot end pattern in binary data and validates that the
    extracted end address matches the pattern's position in the data.

    :param binary_data: Input binary data without offset to U-Boot.
    :param pattern: Pattern to match, defaults to UBOOT_END_PATTERN.
    :return: End address inside tag.
    :raises SPSDKError: If pattern cannot be found in the binary data.
    :raises SPSDKError: If the end address does not match tag position.
    """
    match = re.search(pattern, binary_data)

    if match:
        original_end_address = int(match.group(1))  # Extract the original end address as an integer
        tag_position = match.start()  # Get the starting position of the match

        if original_end_address != tag_position:
            raise SPSDKError(
                "End address does not match the tag position."
                f" {hex(original_end_address)} != {hex(tag_position)}"
            )
        return original_end_address
    raise SPSDKError("Pattern for U-Boot not found in the binary data.")


def replace_uboot(input_binary: str, uboot_path: str) -> int:
    """Replace the existing U-Boot binary in the WIC file with a new U-Boot binary.

    This function reads the WIC binary file, finds the position of the UBOOT_END_PATTERN,
    calculates the new end address based on the size of the new U-Boot binary, and replaces
    the existing U-Boot binary with the new one. It also updates the tag with the new end
    address.

    :param input_binary: Path to the WIC binary file.
    :param uboot_path: Path to the new U-Boot binary file.
    :raises SPSDKError: If the input binary file does not exist.
    :return: New end address of the replaced U-Boot binary.
    """
    if not os.path.exists(input_binary):
        raise SPSDKError(f"File {input_binary} does not exist.")

    with open(input_binary, "rb") as f:
        f.seek(UBOOT_OFFSET)
        binary_data = f.read(READ_LIMIT)

    original_end_address = match_uboot_tag(binary_data)
    uboot_data = load_binary(uboot_path)
    uboot_data = align_block(uboot_data, 0x400)
    new_end_address = len(uboot_data)
    padding = None
    new_tag = generate_tag(new_end_address)
    if new_end_address < original_end_address:
        logger.info("New U-Boot binary is smaller. Adding padding.")
        padding = b"\x00" * (original_end_address - new_end_address + 1)

    with open(input_binary, "r+b") as f:
        f.seek(UBOOT_OFFSET)
        f.write(uboot_data)
        f.write(new_tag)  # Update the tag with the new end address
        if padding:
            f.write(padding)

    logger.info(
        f"U-Boot binary replaced successfully at position {hex(UBOOT_OFFSET)}:{hex(original_end_address)}."
        f" New end address: {hex(new_end_address)}"
    )
    return new_end_address
