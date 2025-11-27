#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2017-2018 Martin Olejar
# Copyright 2019-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK image processing miscellaneous utilities.

This module provides various helper functions for image data manipulation,
including hexadecimal formatting, data reading operations, and dictionary
comparison utilities used across SPSDK image processing components.
"""

import io
from io import SEEK_CUR
from typing import Optional, Union

from spsdk.exceptions import SPSDKError
from spsdk.image.exceptions import SPSDKNotEnoughBytesException, SPSDKStreamReadFailed
from spsdk.utils.registers import value_to_int


def hexdump_fmt(data: bytes, tab: int = 4, length: int = 16, sep: str = ":") -> str:
    """Format binary data as hexadecimal dump with configurable layout.

    Creates a formatted hexadecimal representation of binary data with customizable
    indentation, line length, and byte separators for debugging and display purposes.

    :param data: Binary data to be formatted as hexadecimal dump.
    :param tab: Number of spaces for indentation at the beginning of each line.
    :param length: Number of bytes to display per line before wrapping.
    :param sep: Separator character to place between hexadecimal byte values.
    :return: Formatted hexadecimal string representation of the input data.
    """
    text = " " * tab
    for i, j in enumerate(data):
        text += f"{j:02x}{sep}"
        if ((i + 1) % length) == 0:
            text += "\n" + " " * tab
    return text


def modulus_fmt(modulus: bytes, tab: int = 4, length: int = 15, sep: str = ":") -> str:
    """Format modulus bytes into a human-readable hexadecimal string representation.

    The method prepends a null byte to the modulus and formats it using hexdump formatting
    with customizable tabulation, line length, and separator characters.

    :param modulus: The modulus bytes to be formatted.
    :param tab: Number of spaces for indentation, defaults to 4.
    :param length: Maximum number of bytes per line, defaults to 15.
    :param sep: Separator character between hex values, defaults to ":".
    :return: Formatted hexadecimal string representation of the modulus.
    """
    return hexdump_fmt(b"\0" + modulus, tab, length, sep)


def read_raw_data(
    stream: Union[io.BufferedReader, io.BytesIO],
    length: int,
    index: Optional[int] = None,
    no_seek: bool = False,
) -> bytes:
    """Read raw data from a stream at specified position.

    Reads a specified number of bytes from the given stream, optionally seeking to a
    specific position first. Provides error handling for insufficient data and stream
    read failures.

    :param stream: Input stream to read data from (BufferedReader or BytesIO).
    :param length: Number of bytes to read from the stream.
    :param index: Optional position to seek to before reading. If None, reads from
        current position.
    :param no_seek: If True, seeks back to original position after reading.
    :raises SPSDKError: If index or length parameters are negative.
    :raises SPSDKStreamReadFailed: If the stream read operation fails.
    :raises SPSDKNotEnoughBytesException: If insufficient bytes are available to read.
    :return: Raw bytes data read from the stream.
    """
    if index is not None:
        if index < 0:
            raise SPSDKError(f"Index must be non-negative, found {index}")
        if index != stream.tell():
            stream.seek(index)

    if length < 0:
        raise SPSDKError(f"Length must be non-negative, found {length}")

    try:
        data = stream.read(length)
    except Exception as exc:
        raise SPSDKStreamReadFailed(f"stream.read() failed, requested {length} bytes") from exc

    if len(data) != length:
        raise SPSDKNotEnoughBytesException(
            f"Could not read enough bytes, expected {length}, found {len(data)}"
        )

    if no_seek:
        stream.seek(-length, SEEK_CUR)

    return data


def dict_diff(main: dict, mod: dict) -> dict:
    """Calculate the difference between two dictionaries.

    Compares two dictionaries and returns a new dictionary containing only the values
    from the modified dictionary that differ from the main dictionary. Keys that are
    not present in the main dictionary are skipped. Supports nested dictionaries
    and handles both numeric and non-numeric value comparisons.

    :param main: The reference dictionary to compare against.
    :param mod: The modified dictionary containing potential changes.
    :return: Dictionary containing only the differing values from mod dictionary.
    """
    diff = {}
    for key, value in mod.items():
        if isinstance(value, dict):
            sub = dict_diff(main[key], value)
            if sub:
                diff[key] = sub
        else:
            if key not in main:
                continue
            main_value = main[key] if isinstance(main, dict) else main
            try:
                if value_to_int(main_value) != value_to_int(value):
                    diff[key] = value
            except (SPSDKError, TypeError):
                # Not a number!
                if main_value != value:
                    diff[key] = value
    return diff
