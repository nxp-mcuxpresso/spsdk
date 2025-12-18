#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK miscellaneous utilities and helper functions.

This module provides a collection of utility functions and classes used throughout
the SPSDK library, including data manipulation, file operations, configuration
loading, and various helper utilities for binary data processing.
"""

import contextlib
import hashlib
import json
import logging
import math
import os
import re
import struct
import textwrap
import time
from enum import Enum
from math import ceil
from pathlib import Path
from struct import pack, unpack
from typing import Any, Callable, Generator, Iterable, Iterator, Optional, Type, TypeVar, Union

import yaml

from spsdk import SPSDK_SECRETS_PATH
from spsdk.crypto.rng import random_bytes
from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.exceptions import SPSDKTimeoutError

# for generics
T = TypeVar("T")  # pylint: disable=invalid-name

logger = logging.getLogger(__name__)


class Endianness(str, Enum):
    """Endianness enumeration for byte order specification.

    This enumeration defines the byte order options used throughout SPSDK
    for data processing and binary operations.

    :cvar BIG: Big-endian byte order representation.
    :cvar LITTLE: Little-endian byte order representation.
    """

    BIG = "big"
    LITTLE = "little"

    @classmethod
    def values(cls) -> list[str]:
        """Get enumeration values.

        :return: List of all enumeration values as strings.
        """
        return [mem.value for mem in Endianness.__members__.values()]


class BinaryPattern:
    """Binary pattern generator for creating filled data blocks.

    This class provides functionality to generate binary data blocks filled with
    various patterns including special patterns (random, zeros, ones, incremental)
    and custom numeric values that can be repeated to fill the entire block.

    Supported patterns:
        - rand: Random Pattern
        - zeros: Filled with zeros
        - ones: Filled with all ones
        - inc: Filled with repeated numbers incremented by one 0-0xff
        - any kind of number, that will be repeated to fill up whole image.
          The format could be decimal, hexadecimal, bytes.

    :cvar SPECIAL_PATTERNS: List of supported special pattern names.
    """

    SPECIAL_PATTERNS = ["rand", "zeros", "ones", "inc"]

    def __init__(self, pattern: str) -> None:
        """Initialize binary pattern generator.

        Creates a new binary pattern generator that can produce data based on the specified
        pattern type. Supports predefined patterns (rand, zeros, ones, inc) and custom
        numeric values that will be repeated to fill the target data.

        :param pattern: Pattern specification - predefined patterns (rand, zeros, ones, inc)
            or numeric value in decimal/hexadecimal/bytes format to be repeated
        :raises SPSDKValueError: Unsupported pattern detected.
        """
        try:
            value_to_int(pattern)
        except SPSDKError:
            if pattern not in BinaryPattern.SPECIAL_PATTERNS:
                raise SPSDKValueError(  # pylint: disable=raise-missing-from
                    f"Unsupported input pattern {pattern}"
                )

        self._pattern = pattern

    def get_block(self, size: int) -> bytes:
        """Get block filled with pattern.

        Generate a block of bytes with the specified size using the configured pattern.
        Supports predefined patterns (zeros, ones, rand, inc) and custom byte patterns.

        :param size: Size of block to return in bytes.
        :return: Block of bytes filled with the specified pattern.
        """
        if self._pattern == "zeros":
            return bytes(size)

        if self._pattern == "ones":
            return bytes(b"\xff" * size)

        if self._pattern == "rand":
            return random_bytes(size)

        if self._pattern == "inc":
            return bytes((x & 0xFF for x in range(size)))

        pattern = value_to_bytes(self._pattern, align_to_2n=False)
        block = bytes(pattern * (int((size / len(pattern))) + 1))
        return block[:size]

    @property
    def pattern(self) -> str:
        """Get the pattern in string representation.

        Converts the internal pattern to hexadecimal format if it's a numeric value,
        otherwise returns the pattern as-is.

        :return: Pattern as hexadecimal string if numeric, otherwise original string pattern.
        """
        try:
            return hex(value_to_int(self._pattern))
        except SPSDKError:
            return self._pattern


def align(number: int, alignment: int = 4) -> int:
    """Align number to specified byte boundary.

    The function aligns the input number up to the nearest multiple of the specified
    alignment value. This is commonly used for memory alignment requirements where
    data must be positioned at specific byte boundaries.

    :param number: The number to be aligned (size or address).
    :param alignment: The boundary alignment value, typically a power of 2 (4, 8, 16).
    :return: Aligned number that is always greater than or equal to the input number.
    :raises SPSDKError: When alignment is non-positive or number is negative.
    """
    if alignment <= 0 or number < 0:
        raise SPSDKError("Wrong alignment")

    return (number + (alignment - 1)) // alignment * alignment


def align_block(
    data: Union[bytes, bytearray],
    alignment: int = 4,
    padding: Optional[Union[int, str, BinaryPattern]] = None,
) -> bytes:
    """Align binary data block length to specified boundary by adding padding bytes to the end.

    :param data: Binary data to be aligned.
    :param alignment: Boundary alignment in bytes (typically 2, 4, 16, 64 or 256).
    :param padding: Padding byte value, string pattern, or BinaryPattern instance to use.
    :return: Aligned binary data block.
    :raises SPSDKError: When alignment value is invalid.
    """
    assert isinstance(data, (bytes, bytearray))

    if alignment < 0:
        raise SPSDKError("Wrong alignment")
    current_size = len(data)
    num_padding = align(current_size, alignment) - current_size
    if not num_padding:
        return bytes(data)
    if not padding:
        padding = BinaryPattern("zeros")
    elif not isinstance(padding, BinaryPattern):
        padding = BinaryPattern(str(padding))
    return bytes(data + padding.get_block(num_padding))


def align_block_fill_random(data: bytes, alignment: int = 4) -> bytes:
    """Align block data to specified boundary using random padding.

    This function extends align_block functionality by automatically using random data
    for padding instead of requiring a padding parameter.

    :param data: Input binary data to be aligned.
    :param alignment: Byte boundary for alignment, defaults to 4 bytes.
    :return: Aligned binary data with random padding if needed.
    """
    return align_block(data, alignment, BinaryPattern("rand"))


def extend_block(data: bytes, length: int, padding: int = 0) -> bytes:
    """Extend binary data block with padding to reach specified length.

    Add padding bytes to the end of a binary data block to extend its length
    to the specified value. If the target length equals current length, returns
    the original data unchanged.

    :param data: Binary block to be extended.
    :param length: Requested block length; must be >= current block length.
    :param padding: 8-bit value to be used as padding (default: 0).
    :return: Block extended with padding bytes.
    :raises SPSDKError: When the length is smaller than current block length.
    """
    current_len = len(data)
    if length < current_len:
        raise SPSDKError("Incorrect length")
    num_padding = length - current_len
    if not num_padding:
        return data
    return data + bytes([padding]) * num_padding


def clean_up_file_name(original_name: str) -> str:
    """Clean up the file name by removing invalid characters.

    Removes characters that are not allowed in file names on Windows systems
    including: < > : " | ? * \

    :param original_name: Input file name to be sanitized.
    :return: Sanitized file name with invalid characters removed.
    """
    invalid_characters = '<>:"|?*\\'
    for ch in invalid_characters:
        original_name = original_name.replace(ch, "")

    return original_name


def find_first(iterable: Iterable[T], predicate: Callable[[T], bool]) -> Optional[T]:
    """Find first element from iterable that matches the given condition.

    :param iterable: Iterable collection of elements to search through.
    :param predicate: Function that takes an element and returns True if it matches the condition.
    :return: First matching element or None if no element matches the predicate.
    """
    return next((a for a in iterable if predicate(a)), None)


def load_binary(path: str, search_paths: Optional[list[str]] = None) -> bytes:
    """Load binary file into bytes.

    The method loads a binary file from the specified path or searches for it
    in the provided search paths if the direct path doesn't exist.

    :param path: Path to the binary file to load.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :return: Content of the binary file as bytes.
    """
    data = load_file(path, mode="rb", search_paths=search_paths)
    assert isinstance(data, bytes)
    return data


def load_text(path: str, search_paths: Optional[list[str]] = None) -> str:
    """Load text file content into string.

    The method loads a text file and returns its content as a string. It supports
    searching for the file in multiple directories if search paths are provided.

    :param path: Path to the text file to load.
    :param search_paths: List of directories to search for the file, defaults to None.
    :return: Content of the text file as string.
    """
    text = load_file(path, mode="r", search_paths=search_paths)
    assert isinstance(text, str)
    return text


def load_file(
    path: str, mode: str = "r", search_paths: Optional[list[str]] = None
) -> Union[str, bytes]:
    """Load file content from specified path.

    The method searches for the file in provided search paths and loads its content
    either as text or binary data based on the specified mode.

    :param path: Path to the file to be loaded.
    :param mode: File reading mode, 'r' for text or 'rb' for binary.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :return: File content as string (text mode) or bytes (binary mode).
    """
    path = find_file(path, search_paths=search_paths)
    logger.debug(f"Loading {'binary' if 'b' in mode else 'text'} file from {path}")
    encoding = None if "b" in mode else "utf-8"
    with open(path, mode, encoding=encoding) as f:
        return f.read()


def write_file(
    data: Union[str, bytes],
    path: str,
    mode: str = "w",
    encoding: str = "utf-8",
    overwrite: bool = True,
) -> int:
    """Write data to a file with automatic directory creation and overwrite protection.

    The method automatically creates parent directories if they don't exist and supports
    both text and binary modes. When overwrite is disabled, it generates a unique filename
    by appending a counter to avoid conflicts.

    :param data: Data to write to the file.
    :param path: Path to the target file.
    :param mode: File writing mode ('w' for text, 'wb' for binary), defaults to 'w'.
    :param encoding: Text encoding ('ascii', 'utf-8'), defaults to 'utf-8'.
    :param overwrite: Whether to overwrite existing files, defaults to True.
    :return: Number of characters or bytes written to the file.
    """
    path = path.replace("\\", "/")
    folder = os.path.dirname(path)
    if folder and not os.path.exists(folder):
        os.makedirs(folder, exist_ok=True)

    # If overwrite is False and file exists, modify path by appending number
    if not overwrite and os.path.exists(path):
        base_path, ext = os.path.splitext(path)
        counter = 1
        new_path = f"{base_path}_{counter}{ext}"
        while os.path.exists(new_path):
            counter += 1
            new_path = f"{base_path}_{counter}{ext}"
        path = new_path
        logger.debug(f"File already exists. Saving to {path} instead")

    logger.debug(f"Storing {'binary' if 'b' in mode else 'text'} file at {path}")
    with open(path, mode, encoding=None if "b" in mode else encoding) as f:
        return f.write(data)


def get_abs_path(file_path: str, base_dir: Optional[str] = None) -> str:
    """Convert relative or absolute file path to normalized absolute path.

    The method handles both relative and absolute paths, normalizing path separators
    to forward slashes for cross-platform compatibility.

    :param file_path: File path to be converted to absolute path.
    :param base_dir: Base directory to create absolute path, if not specified the system CWD is used.
    :return: Absolute file path with normalized separators.
    """
    if os.path.isabs(file_path):
        return file_path.replace("\\", "/")

    return os.path.abspath(os.path.join(base_dir or os.getcwd(), file_path)).replace("\\", "/")


def _find_path(
    path: str,
    check_func: Callable[[str], bool],
    use_cwd: bool = True,
    search_paths: Optional[list[str]] = None,
    raise_exc: bool = True,
) -> str:
    """Find and return the full path to a file or directory.

    The method searches for the given path in multiple locations with configurable search order.
    Search paths take precedence over current working directory when both are specified.

    :param path: File name, part of file path or full path to search for.
    :param check_func: Function to validate if the found path exists and meets criteria.
    :param use_cwd: Try current working directory to find the file, defaults to True.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :param raise_exc: Raise exception if file is not found, defaults to True.
    :return: Full absolute path to the found file or empty string if not found and raise_exc is False.
    :raises SPSDKError: File not found in any of the searched locations.
    """
    path = path.replace("\\", "/")

    if os.path.isabs(path):
        if not check_func(path):
            if raise_exc:
                raise SPSDKError(f"Path '{path}' not found")
            return ""
        return path
    if search_paths:
        for dir_candidate in search_paths:
            if not dir_candidate:
                continue
            dir_candidate = dir_candidate.replace("\\", "/")
            path_candidate = get_abs_path(path, base_dir=dir_candidate)
            if check_func(path_candidate):
                return path_candidate
    if use_cwd and check_func(path):
        return get_abs_path(path)
    # list all directories in error message
    searched_in: list[str] = []
    if use_cwd:
        searched_in.append(os.path.abspath(os.curdir))
    if search_paths:
        searched_in.extend(filter(None, search_paths))
    searched_in = [s.replace("\\", "/") for s in searched_in]
    err_str = f"Path '{path}' not found, Searched in: {', '.join(searched_in)}"
    if not raise_exc:
        logger.debug(err_str)
        return ""
    raise SPSDKError(err_str)


def find_dir(
    dir_path: str,
    use_cwd: bool = True,
    search_paths: Optional[list[str]] = None,
    raise_exc: bool = True,
) -> str:
    """Find directory path with flexible search options.

    The method searches for a directory using multiple strategies: absolute path check,
    current working directory search, and custom search paths. Search paths take
    precedence over current working directory when both are specified.

    :param dir_path: Directory name, part of directory path or full path
    :param use_cwd: Try current working directory to find the directory, defaults to True
    :param search_paths: List of paths where to search for the directory, defaults to None
    :param raise_exc: Raise exception if directory is not found, defaults to True
    :return: Full path to the directory
    :raises SPSDKError: Directory not found
    """
    return _find_path(
        path=dir_path,
        check_func=os.path.isdir,
        use_cwd=use_cwd,
        search_paths=search_paths,
        raise_exc=raise_exc,
    )


def find_file(
    file_path: str,
    use_cwd: bool = True,
    search_paths: Optional[list[str]] = None,
    raise_exc: bool = True,
) -> str:
    """Find file in filesystem using multiple search strategies.

    The method searches for a file by checking the provided path directly, then optionally
    searching in the current working directory and additional search paths. Search paths
    take precedence over current working directory when both are enabled.

    :param file_path: File name, part of file path or full path to search for.
    :param use_cwd: Try current working directory to find the file, defaults to True.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :param raise_exc: Raise exception if file is not found, defaults to True.
    :return: Full absolute path to the found file.
    :raises SPSDKError: File not found in any of the search locations.
    """
    return _find_path(
        path=file_path,
        check_func=os.path.isfile,
        use_cwd=use_cwd,
        search_paths=search_paths,
        raise_exc=raise_exc,
    )


@contextlib.contextmanager
def use_working_directory(path: str) -> Iterator[None]:
    # pylint: disable=missing-yield-doc
    """Execute the block in given directory.

    Changes current directory to the specified path, executes the block,
    and restores the original directory afterwards.

    :param path: The path where the current directory will be changed to.
    :return: Iterator for context manager usage.
    """
    current_dir = os.getcwd()
    try:
        os.chdir(path)
        yield
    finally:
        os.chdir(current_dir)
        if os.getcwd() != current_dir:
            logger.warning(f"Directory was not changed back to the original one: {current_dir}")


def format_value(value: int, size: int, delimiter: str = "_", use_prefix: bool = True) -> str:
    """Convert integer value to formatted binary or hexadecimal string representation.

    The function automatically selects binary format when size is not divisible by 8,
    otherwise uses hexadecimal format. Digits are grouped by 4 characters using the
    specified delimiter for better readability.

    :param value: Integer value to be converted.
    :param size: Bit size that determines output format and padding.
    :param delimiter: Character used to separate digit groups, defaults to underscore.
    :param use_prefix: Whether to include format prefix (0b/0x), defaults to True.
    :return: Formatted string representation of the value.
    """
    padding = size if size % 8 else (size // 8) * 2
    infix = "b" if size % 8 else "x"
    sign = "-" if value < 0 else ""
    parts = re.findall(".{1,4}", f"{abs(value):0{padding}{infix}}"[::-1])
    rev = delimiter.join(parts)[::-1]
    prefix = f"0{infix}" if use_prefix else ""
    return f"{sign}{prefix}{rev}"


def get_bytes_cnt_of_int(
    value: int, align_to_2n: bool = True, byte_cnt: Optional[int] = None
) -> int:
    """Calculate the minimum number of bytes needed to store an integer value.

    The method determines the byte count required for integer storage with optional
    alignment to standard sizes and validation against a specified byte count.

    :param value: Input integer value to analyze.
    :param align_to_2n: If True, align result to standard sizes (1,2,4,8,12,16,20...).
    :param byte_cnt: Optional fixed byte count to validate against and return.
    :raises SPSDKValueError: The integer input value doesn't fit into byte_cnt.
    :return: Number of bytes needed to store the integer.
    """
    cnt = 0
    if value == 0:
        return byte_cnt or 1

    while value != 0:
        value >>= 8
        cnt += 1

    if align_to_2n and cnt > 2:
        cnt = int(ceil(cnt / 4)) * 4

    if byte_cnt and cnt > byte_cnt:
        raise SPSDKValueError(
            f"Value takes more bytes than required byte count {byte_cnt} after align."
        )

    cnt = byte_cnt or cnt

    return cnt


def value_to_int(value: Union[bytes, bytearray, int, str], default: Optional[int] = None) -> int:
    """Convert value from multiple formats to integer.

    Supports conversion from integers, bytes, bytearrays, and string representations
    (including binary, octal, decimal, and hexadecimal formats with optional prefixes).

    :param value: Input value to convert (int, bytes, bytearray, or str).
    :param default: Default value returned when conversion fails.
    :return: Converted integer value.
    :raises SPSDKError: Unsupported input type or invalid conversion without default.
    """
    if isinstance(value, int):
        return value

    if isinstance(value, (bytes, bytearray)):
        return int.from_bytes(value, Endianness.BIG.value)

    if isinstance(value, str) and value != "":
        match = re.match(
            r"(?P<prefix>0[box])?(?P<number>[0-9a-f_]+)(?P<suffix>[ul]{0,3})$",
            value.strip().lower(),
        )
        if match:
            base = {"0b": 2, "0o": 8, "0": 10, "0x": 16, None: 10}[match.group("prefix")]
            try:
                return int(match.group("number"), base=base)
            except ValueError:
                pass

    if default is not None:
        return default
    raise SPSDKError(f"Invalid input number type({type(value)}) with value ({value})")


def value_to_bytes(
    value: Union[bytes, bytearray, int, str],
    align_to_2n: bool = True,
    byte_cnt: Optional[int] = None,
    endianness: Endianness = Endianness.BIG,
) -> bytes:
    """Convert value from multiple formats to bytes representation.

    The function accepts various input types (bytes, bytearray, int, str) and converts them
    to a standardized bytes format with configurable alignment and endianness.

    :param value: Input value to be converted to bytes.
    :param align_to_2n: When True, aligns the output length to powers of 2 (1,2,4,8,16...).
    :param byte_cnt: Specific number of bytes for the result, overrides alignment.
    :param endianness: Byte order for the result ('big' or 'little' endian).
    :return: Value converted to bytes format.
    """
    if isinstance(value, bytes):
        return value

    if isinstance(value, bytearray):
        return bytes(value)

    value = value_to_int(value)
    return value.to_bytes(
        get_bytes_cnt_of_int(value, align_to_2n, byte_cnt=byte_cnt), endianness.value
    )


def value_to_bool(value: Optional[Union[bool, int, str]]) -> bool:
    """Convert various input formats to boolean value.

    The function accepts boolean, integer, string, or None values and converts them
    to boolean. For strings, it recognizes "True", "true", "T", and "1" as True,
    all other strings as False. For other types, uses Python's built-in bool() conversion.

    :param value: Input value to convert (bool, int, str, or None).
    :return: Boolean representation of the input value.
    :raises SPSDKError: Unsupported input type.
    """
    if isinstance(value, str):
        return value in ("True", "true", "T", "1")

    return bool(value)


def load_hex_string(
    source: Optional[Union[str, int, bytes]],
    expected_size: int,
    search_paths: Optional[list[str]] = None,
    name: Optional[str] = "key",
) -> bytes:
    """Load hexadecimal data from various sources.

    The method supports loading from file paths, direct hexadecimal strings, bytes, or integers.
    If no source is provided, a random value of the expected size is generated. The method
    handles both text files containing hex strings and binary files.

    :param source: File path, hexadecimal string, bytes, or integer. Random value if None.
    :param expected_size: Expected size of the data in bytes.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :param name: Name for the key/data to load, defaults to "key".
    :raises SPSDKError: Invalid input data or size mismatch.
    :return: Data in bytes with the expected size.
    """
    if not source:
        logger.warning(
            f"The key source is not specified, the random value is used in size of {expected_size} B."
        )
        return random_bytes(expected_size)

    key = None
    if expected_size < 1:
        raise SPSDKError(f"Expected size of key must be positive. Got: {expected_size}")

    if isinstance(source, (bytes, int)):
        return value_to_bytes(source, byte_cnt=expected_size)

    try:
        file_path = find_file(source, search_paths=search_paths)
        try:
            str_key = load_file(file_path)
            assert isinstance(str_key, str)
            if not str_key.startswith(("0x", "0X")):
                str_key = "0x" + str_key
            key = value_to_bytes(str_key, byte_cnt=expected_size)
            if len(key) != expected_size:
                raise SPSDKError(f"Invalid {name} size. Expected: {expected_size}, got: {len(key)}")
        except (SPSDKError, UnicodeDecodeError):
            key = load_binary(file_path)
    except Exception:
        try:
            if not source.startswith(("0x", "0X")):
                source = "0x" + source
            key = value_to_bytes(source, byte_cnt=expected_size)
        except SPSDKError:
            pass

    if key is None:
        raise SPSDKError(f"Invalid key input: {source}")
    if len(key) != expected_size:
        raise SPSDKError(f"Invalid {name} size. Expected: {expected_size}, got: {len(key)}")

    return key


def reverse_bytes_in_longs(arr: bytes) -> bytes:
    """Reverse byte order in 32-bit words from input bytes array.

    The function processes the input bytes array in 4-byte chunks (32-bit words) and reverses
    the byte order within each word. The input array length must be divisible by 4.

    :param arr: Input bytes array to process, must be divisible by 4.
    :raises SPSDKError: Input array length is not divisible by 4.
    :return: New bytes array with reversed byte order in each 32-bit word.
    """
    arr_len = len(arr)
    if arr_len % 4 != 0:
        raise SPSDKError("The input array is not in modulo 4!")

    result = bytearray()

    for x in range(0, arr_len, 4):
        word = bytearray(arr[x : x + 4])
        word.reverse()
        result.extend(word)
    return bytes(result)


def change_endianness(bin_data: bytes) -> bytes:
    """Convert binary format used in files to binary used in register object.

    The method handles endianness conversion for different data lengths. Single bytes are
    returned unchanged, 2-byte values are reversed, 3-byte values are not supported, and
    longer values use specialized long word reversal.

    :param bin_data: Input binary array to convert endianness.
    :return: Converted array with changed endianness (little to big endian conversion).
    :raises SPSDKError: Unsupported length (3 bytes) for endianness conversion.
    """
    data = bytearray(bin_data)
    length = len(data)
    if length == 1:
        return data

    if length == 2:
        data.reverse()
        return data

    # The length of 24 bits is not supported yet
    if length == 3:
        raise SPSDKError("Unsupported length (3) for change endianness.")

    return reverse_bytes_in_longs(data)


class Timeout:
    """Timeout handler for SPSDK operations.

    This class provides timeout functionality with configurable time units and methods
    to track elapsed time and remaining time during operations. It supports microseconds,
    milliseconds, and seconds as time units.

    :cvar UNITS: Supported time units and their conversion factors to microseconds.
    """

    UNITS = {
        "s": 1000000,
        "ms": 1000,
        "us": 1,
    }

    def __init__(self, timeout: int, units: str = "s") -> None:
        """Initialize timeout class with specified timeout value and units.

        :param timeout: Timeout value in specified units.
        :param units: Timeout units (MUST be from the UNITS list).
        :raises SPSDKValueError: Invalid input value.
        """
        if units not in self.UNITS:
            raise SPSDKValueError("Units are not in supported units.")
        self.enabled = timeout != 0
        self.timeout_us = timeout * self.UNITS[units]
        self.start_time_us = self._get_current_time_us()
        self.end_time = self.start_time_us + self.timeout_us
        self.units = units

    @staticmethod
    def _get_current_time_us() -> int:
        """Get current system time in microseconds.

        The method returns the current system time as an integer value in microseconds,
        using the system's time.time() function and converting it to microseconds with
        ceiling rounding.

        :return: Current time in microseconds as integer.
        """
        return ceil(time.time() * 1_000_000)

    def _convert_to_units(self, time_us: int) -> int:
        """Convert time from microseconds to the configured time units.

        :param time_us: Time value in microseconds.
        :return: Time value converted to the configured units.
        """
        return time_us // self.UNITS[self.units]

    def get_consumed_time(self) -> int:
        """Get consumed time since start of timeout operation.

        :return: Consumed time in units as the class was constructed.
        """
        return self._convert_to_units(self._get_current_time_us() - self.start_time_us)

    def get_consumed_time_ms(self) -> int:
        """Get consumed time since start of timed out operation in milliseconds.

        :return: Consumed time in milliseconds.
        """
        return (self._get_current_time_us() - self.start_time_us) // 1000

    def get_rest_time(self, raise_exc: bool = False) -> int:
        """Get remaining time until timeout expiration.

        The method calculates how much time is left before the timeout occurs. If the timeout
        has already expired and raise_exc is True, an exception will be raised.

        :param raise_exc: If True, raises SPSDKTimeoutError when timeout has expired.
        :return: Remaining time in the same units used during class construction.
        :raises SPSDKTimeoutError: When timeout has expired and raise_exc is True.
        """
        if self.enabled and self._get_current_time_us() > self.end_time and raise_exc:
            raise SPSDKTimeoutError("Timeout of operation.")

        return (
            self._convert_to_units(self.end_time - self._get_current_time_us())
            if self.enabled
            else 0
        )

    def get_rest_time_ms(self, raise_exc: bool = False) -> int:
        """Get remaining time until timeout overflow.

        :param raise_exc: If set, the function raises SPSDKTimeoutError in case of overflow.
        :return: Remaining time in milliseconds.
        :raises SPSDKTimeoutError: In case of timeout overflow when raise_exc is True.
        """
        if self.enabled and self._get_current_time_us() > self.end_time and raise_exc:
            raise SPSDKTimeoutError("Timeout of operation.")

        # pylint: disable=superfluous-parens     # because PEP20: Readability counts
        return ((self.end_time - self._get_current_time_us()) // 1000) if self.enabled else 0

    def overflow(self, raise_exc: bool = False) -> bool:
        """Check if the timer has overflowed.

        The method verifies whether the timer has exceeded its configured timeout period.
        It can optionally raise an exception when overflow is detected.

        :param raise_exc: If True, raises SPSDKTimeoutError when overflow occurs.
        :return: True if timeout has overflowed, False otherwise.
        :raises SPSDKTimeoutError: When overflow occurs and raise_exc is True.
        """
        overflow = self.enabled and self._get_current_time_us() > self.end_time
        if overflow and raise_exc:
            raise SPSDKTimeoutError("Timeout of operation.")
        return overflow


def size_fmt(num: Union[float, int], use_kibibyte: bool = True) -> str:
    """Format byte size into human-readable string representation.

    Converts a numeric byte value into a formatted string with appropriate
    unit suffix (B, kB/KiB, MB/MiB, etc.) for better readability.

    :param num: The byte size value to format.
    :param use_kibibyte: If True, use binary prefixes (1024-based) with 'iB' suffix,
                         if False, use decimal prefixes (1000-based) with 'B' suffix.
    :return: Formatted size string with value and unit (e.g., "1.5 MiB", "1024 B").
    """
    base, suffix = [(1000.0, "B"), (1024.0, "iB")][use_kibibyte]
    i = "B"
    for i in ["B"] + [i + suffix for i in list("kMGTP")]:
        if num < base:
            break
        num /= base

    return f"{int(num)} {i}" if i == "B" else f"{num:3.1f} {i}"


def bytes_to_print(
    data: Optional[bytes], max_length: int = 32, unavailable_text: str = "Not available"
) -> str:
    """Format bytes data for display with length-based truncation.

    Converts bytes data to hexadecimal string representation with optional truncation for long data.
    Returns unavailable text when data is None or empty.

    :param data: Bytes data to format, can be None or empty.
    :param max_length: Maximum number of bytes to display before truncation.
    :param unavailable_text: Text to show when data is None or empty.
    :return: Formatted string representation of the bytes data.
    """
    # Case 1: No bytes - return unavailable text
    if not data:
        return unavailable_text

    # Case 2: Bytes shorter than or equal to max_length - print it all
    if len(data) <= max_length:
        return data.hex()

    # Case 3: Bytes longer than max_length - print shortened with info
    return f"{data[:max_length].hex()}...(truncated to {max_length}, total {len(data)})"


def numberify_version(version: str, separator: str = ".", valid_numbers: int = 3) -> int:
    """Convert version string into a numerical representation.

    Each version component is weighted by powers of 1000 to create a comparable integer.
    This allows for easy version comparison and sorting operations.

    Examples:
        1.2.3    -> 1  * 1_000_000 +   2 * 1_000 + 3 * 1 =  1_002_003
        21.100.9 -> 21 * 1_000_000 + 100 * 1_000 + 9 * 1 = 21_100_009

    :param version: Version string with numbers separated by separator.
    :param separator: Character used to separate version components.
    :param valid_numbers: Maximum number of version components to process.
    :return: Integer representation of the version string.
    """
    sanitized_version = sanitize_version(
        version=version, separator=separator, valid_numbers=valid_numbers
    )
    return int(
        sum(
            int(number) * math.pow(10, 3 * order)
            for order, number in enumerate(reversed(sanitized_version.split(separator)))
        )
    )


def sanitize_version(version: str, separator: str = ".", valid_numbers: int = 3) -> str:
    """Sanitize version string to ensure consistent format.

    The method normalizes version strings by padding with '.0' when there are fewer
    parts than required, or truncating when there are more parts than needed.

    Examples:
        1.2     -> 1.2.0
        1.2.3.4 -> 1.2.3

    :param version: Original version string to be sanitized.
    :param separator: Separator used in the version string, defaults to ".".
    :param valid_numbers: Number of version parts to maintain, defaults to 3.
    :return: Sanitized version string with the specified number of parts.
    """
    version_parts = version.split(separator)
    version_parts += ["0"] * (valid_numbers - len(version_parts))
    return separator.join(version_parts[:valid_numbers])


def get_key_by_val(value: str, dictionary: dict[str, list[str]]) -> str:
    """Return key by its value from dictionary.

    The method performs case-insensitive search through dictionary values to find the
    corresponding key.

    :param value: Value to find in dictionary values.
    :param dictionary: Dictionary with string keys and list of strings as values.
    :raises SPSDKValueError: Value is not present in dictionary.
    :return: Key name corresponding to the found value.
    """
    for key, item in dictionary.items():
        if value.lower() in [x.lower() for x in item]:
            return key

    raise SPSDKValueError(f"Value {value} is not in {dictionary}.")


def swap16(x: int) -> int:
    """Swap bytes in half word (16-bit).

    Takes a 16-bit integer value and swaps its high and low bytes, converting
    between little-endian and big-endian byte order.

    :param x: 16-bit integer value to swap (0x0000 to 0xFFFF).
    :return: Integer with swapped bytes.
    :raises SPSDKError: When input value is outside valid 16-bit range.
    """
    if x < 0 or x > 0xFFFF:
        raise SPSDKError("Incorrect number to be swapped")
    return ((x << 8) & 0xFF00) | ((x >> 8) & 0x00FF)


def swap32(x: int) -> int:
    """Swap 32-bit integer byte order.

    Converts a 32-bit integer from big-endian to little-endian byte order or vice versa.

    :param x: Integer value to be byte-swapped (0 to 0xFFFFFFFF).
    :return: Integer with swapped byte order.
    :raises SPSDKError: When the input value is outside the valid 32-bit range.
    """
    if x < 0 or x > 0xFFFFFFFF:
        raise SPSDKError("Incorrect number to be swapped")
    return unpack("<I", pack(">I", x))[0]


def reverse_bits(x: int, bits_cnt: int = 32) -> int:
    """Reverse bits in integer.

    :param x: Integer to be bit reversed.
    :param bits_cnt: Count of bits to reverse, defaults to 32.
    :return: Integer with reversed bit order.
    """
    str_bits_format = "{:0{bits_cnt}b}".format(x, bits_cnt=bits_cnt)
    return int(str_bits_format[::-1], 2)


def check_range(x: int, start: int = 0, end: int = (1 << 32) - 1) -> bool:
    """Check if the number is in range.

    :param x: Number to check.
    :param start: Lower border of range, default is 0.
    :param end: Upper border of range, default is unsigned 32-bit range.
    :return: True if fits, False otherwise.
    """
    if start > x > end:
        return False

    return True


def load_configuration(path: str, search_paths: Optional[list[str]] = None) -> dict:
    """Load configuration from YAML or JSON file.

    The method attempts to parse the file content as JSON first, then falls back
    to YAML parsing if JSON parsing fails. It uses SecretsLoader for YAML parsing
    to handle sensitive data securely.

    :param path: Path to configuration file (relative or absolute).
    :param search_paths: List of paths where to search for the file, defaults to None.
    :raises SPSDKError: When file cannot be loaded, parsed, or contains invalid format.
    :return: Content of configuration as dictionary.
    """
    try:
        config = load_text(path, search_paths=search_paths)
    except Exception as exc:
        raise SPSDKError(f"Can't load configuration file: {str(exc)}") from exc

    config_data: Optional[dict] = None
    try:
        config_data = json.loads(config)
    except json.JSONDecodeError:
        try:
            # SecretLoader inherits from SafeLoader, thus using yaml.load is OK
            config_data = yaml.load(config, Loader=SecretsLoader)  # nosec: yaml_load
        except (yaml.YAMLError, UnicodeDecodeError):
            pass

    if not config_data:
        raise SPSDKError(f"Can't parse configuration file: {path}")
    if not isinstance(config_data, dict):
        raise SPSDKError(f"Invalid configuration file: {path}")

    return config_data


def split_data(data: Union[bytearray, bytes], size: int) -> Generator[bytes, None, None]:
    """Split data into chunks of specified size.

    :param data: Array of bytes to be split into chunks.
    :param size: Size of each chunk in bytes.
    :return: Generator yielding byte chunks of the specified size.
    """
    for i in range(0, len(data), size):
        yield data[i : i + size]


def get_hash(text: Union[str, bytes]) -> str:
    """Get hash of given text.

    Computes SHA256 hash of the input text and returns first 8 characters of the hexadecimal digest.

    :param text: Input text to be hashed, either as string or bytes.
    :return: First 8 characters of SHA256 hash in hexadecimal format.
    """
    if isinstance(text, str):
        text = text.encode("utf-8")
    return hashlib.sha256(text).digest().hex()[:8]


def deep_update(d: dict, u: dict) -> dict:
    """Deep update nested dictionaries and lists.

    Recursively merges two dictionaries, updating the first dictionary with values
    from the second. For nested dictionaries, the merge is performed recursively
    rather than replacing the entire nested dictionary. For lists containing
    dictionaries, the dictionaries are also merged recursively.

    :param d: Dictionary that will be updated.
    :param u: Dictionary with update information.
    :return: Updated dictionary.
    """
    for k, v in u.items():
        if isinstance(v, dict):
            d[k] = deep_update(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def wrap_text(text: str, max_line: int = 100) -> str:
    """Wrap text according to SPSDK formatting standards.

    Processes input text by preserving existing line breaks and applying text wrapping
    to each line individually to ensure consistent formatting across the SPSDK project.

    :param text: Input text to be wrapped.
    :param max_line: Maximum line length for wrapped output, defaults to 100.
    :return: Formatted text with appropriate line breaks inserted.
    """
    lines = text.splitlines()
    return "\n".join([textwrap.fill(text=line, width=max_line) for line in lines])


def get_printable_path(path: str) -> str:
    """Get printable path for file display purposes.

    Converts file path to a format suitable for display, with special handling
    for Jupyter notebook environments. When JUPYTER_SPSDK environment variable
    is set to "1", returns relative path from current working directory using
    POSIX format. Otherwise returns the original path unchanged.

    :param path: Absolute or relative file path to convert.
    :return: Display-friendly file path string.
    """
    # check Jupyter env variable
    if "JUPYTER_SPSDK" in os.environ and os.environ["JUPYTER_SPSDK"] == "1":
        return Path(os.path.relpath(path, os.getcwd())).as_posix()
    return path


TS = TypeVar("TS", bound="SingletonMeta")  # pylint: disable=invalid-name


class SingletonMeta(type):
    """Singleton metaclass for ensuring single instance creation.

    This metaclass implements the singleton pattern by overriding the class
    instantiation process to ensure only one instance of a class exists
    throughout the application lifecycle.

    :cvar _instance: Stores the single instance of the class.
    """

    _instance = None

    def __call__(cls: Type[TS], *args: Any, **kwargs: Any) -> TS:  # type: ignore
        """Create or return singleton instance of the class.

        This method implements the singleton pattern by ensuring only one instance
        of the class exists. If no instance exists, it creates one using the parent
        class constructor. If an instance already exists, it returns the existing
        instance.

        :param cls: The class type to instantiate.
        :param args: Positional arguments to pass to the class constructor.
        :param kwargs: Keyword arguments to pass to the class constructor.
        :return: The singleton instance of the class.
        """
        if cls._instance is None:
            instance = super().__call__(*args, **kwargs)
            cls._instance = instance
        return cls._instance


def load_secret(value: str, search_paths: Optional[list[str]] = None) -> str:
    """Load secret text from the configuration value.

    The method supports multiple input formats for flexible secret loading:
    1. If the value is an existing path, first line of file is read and returned
    2. If the value has format '$ENV_VAR', the value of environment variable ENV_VAR is returned
    3. If the value has format '$ENV_VAR' and the value contains a valid path to a file,
    the first line of a file is returned
    4. If the value does not match any options above, the input value itself is returned

    Note that the value with an initial component of ~ or ~user is replaced by that user's
    home directory.

    :param value: Input string to be used for loading the secret.
    :param search_paths: List of paths where to search for the file, defaults to None.
    :return: The actual secret value.
    """
    # value of api_key may contain '~' for user home or '$' for environment variable
    value = os.path.expanduser(os.path.expandvars(value))
    try:
        file = find_file(file_path=value, search_paths=search_paths)
        with open(file, encoding="utf-8") as f:
            value = f.readline().strip()
    except SPSDKError:
        pass
    return value


def swap_bytes(data: bytes) -> bytes:
    """Swap individual bytes in pairs.

    Swaps adjacent bytes in the input data. For example, b'abcd' becomes b'badc'.
    If the input has an odd number of bytes, the last byte remains unchanged.

    :param data: Input bytes to swap.
    :return: Bytes with adjacent pairs swapped.
    """
    data_array = bytearray(data)
    data_array[0::2], data_array[1::2] = data_array[1::2], data_array[0::2]
    return bytes(data_array)


class SecretManager(metaclass=SingletonMeta):
    """SPSDK Secret Manager for secure configuration data handling.

    This singleton class manages secrets loaded from YAML configuration files with
    lazy loading and caching capabilities. It provides secure access to sensitive
    configuration data across the SPSDK library while ensuring secrets are loaded
    only when needed and cached for performance.

    :cvar secrets_path: Path to the secrets YAML file location.
    """

    _secrets: Optional[dict[str, Any]] = None
    secrets_path = SPSDK_SECRETS_PATH

    def get_secret(self, key: str) -> Any:
        """Get a secret by key, loading the secrets file if needed.

        :param key: The key of the secret to retrieve.
        :raises ValueError: If the secret key is not found.
        :return: The secret value.
        """
        if self._secrets is None:
            self._load_secrets()

        assert self._secrets
        if key not in self._secrets:
            raise ValueError(f"Secret '{key}' not found in secrets file ({self.secrets_path})")

        return self._secrets[key]

    def _load_secrets(self) -> None:
        """Load secrets from the secrets file.

        The method initializes an empty dictionary if the secrets file doesn't exist, otherwise
        loads and parses the YAML content from the file.

        :raises yaml.YAMLError: If the secrets file contains invalid YAML.
        """
        if not os.path.exists(self.secrets_path):
            self._secrets = {}  # Initialize with empty dict if file doesn't exist
            return

        with open(self.secrets_path, "r", encoding="utf-8") as f:
            self._secrets = yaml.safe_load(f) or {}


def secret_constructor(loader: yaml.SafeLoader, node: yaml.ScalarNode) -> Any:
    """Custom YAML constructor to load secrets from the secrets file.

    :param loader: YAML loader instance.
    :param node: YAML node representing the secret key.
    :return: Secret value corresponding to the key.
    :raises ValueError: If the secret key is not found.
    """
    key = loader.construct_scalar(node)
    return SecretManager().get_secret(key)


class SecretsLoader(yaml.SafeLoader):
    """YAML loader for SPSDK configuration files with secret tag support.

    This custom YAML loader extends SafeLoader to handle special !secret tags
    in configuration files, enabling secure loading of sensitive data like
    passwords, keys, and tokens from external sources.
    """


# Register the !secret tag constructor with our custom loader
SecretsLoader.add_constructor("!secret", secret_constructor)


def swap_endianness(data: bytes, word_size: int = 4) -> bytes:
    """Convert between little-endian and big-endian byte order for data consisting of fixed-size words.

    The method swaps the endianness of input data by treating it as a sequence of words of the
    specified size. Supports 16-bit, 32-bit, and 64-bit word sizes.

    :param data: Input data bytes to swap endianness.
    :param word_size: Size of each word in bytes (default: 4 for 32-bit words).
    :return: Data with swapped endianness.
    :raises SPSDKError: If word_size is not supported or data length is not a multiple of word_size.
    """
    if word_size not in (2, 4, 8):
        raise SPSDKError(
            f"Unsupported word size: {word_size}. Supported sizes are 2, 4, and 8 bytes."
        )

    if len(data) % word_size != 0:
        raise SPSDKError(f"Data length ({len(data)}) is not a multiple of word size ({word_size}).")

    format_map = {
        2: ("<H", ">H"),  # 16-bit word
        4: ("<I", ">I"),  # 32-bit word
        8: ("<Q", ">Q"),  # 64-bit word
    }
    little_format, big_format = format_map[word_size]

    return b"".join(
        struct.pack(big_format, struct.unpack(little_format, data[i : i + word_size])[0])
        for i in range(0, len(data), word_size)
    )
