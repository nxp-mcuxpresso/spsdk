#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK miscellaneous utilities.

This module contains comprehensive test cases for the SPSDK misc utilities module,
covering data alignment operations, file I/O operations, value conversions,
endianness handling, bit manipulation, and timeout functionality.
"""

import filecmp
import os
import time
from typing import Any, Optional, Union
from unittest.mock import patch

import pytest

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.exceptions import SPSDKTimeoutError
from spsdk.utils.misc import (
    BinaryPattern,
    Timeout,
    align,
    align_block,
    align_block_fill_random,
    change_endianness,
    extend_block,
    find_file,
    find_first,
    format_value,
    get_bytes_cnt_of_int,
    load_binary,
    load_file,
    load_secret,
    reverse_bits,
    reverse_bytes_in_longs,
    size_fmt,
    swap16,
    use_working_directory,
    value_to_bool,
    value_to_bytes,
    value_to_int,
    write_file,
)


@pytest.mark.parametrize(
    "test_input,alignment,expected",
    [
        (0, 4, 0),
        (1, 4, 4),
        (2, 4, 4),
        (3, 4, 4),
        (4, 4, 4),
        (5, 4, 8),
        (1, 255, 255),
        (256, 255, 2 * 255),
        (1, 65535, 65535),
        (1, 65536, 65536),
        (65535, 65536, 65536),
        (0x7FFFFFFF, 0x80000000, 0x80000000),
        (0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF),
    ],
)
def test_align(test_input: int, alignment: int, expected: int) -> None:
    """Test the align function with given input and alignment values.

    Verifies that the align function correctly aligns the test_input value
    to the specified alignment boundary and returns the expected result.

    :param test_input: The input value to be aligned.
    :param alignment: The alignment boundary value.
    :param expected: The expected aligned result value.
    """
    assert align(test_input, alignment) == expected


@pytest.mark.parametrize(
    "test_input,alignment,padding,expected",
    [
        # no change in empty data
        (b"", 4, 0, b""),
        (b"", 1024, 0, b""),
        # no change for alignment == 1
        (b"\x00", 1, 0, b"\x00"),
        (b"\x00\x01\x02\x03", 2, 0xFF, b"\x00\x01\x02\x03"),
        (b"\x00\x01\x02\x03", 4, 0xFF, b"\x00\x01\x02\x03"),
        # align to 3
        (b"\x00", 3, 1, b"\x00\x01\x01"),
        # align to 4
        (b"\x00", 4, 0, b"\x00\x00\x00\x00"),
        (b"\x00", 4, 0xFF, b"\x00\xff\xff\xff"),
        # align to 16
        (b"\x02", 16, 2, b"\x02" * 16),
    ],
)
def test_align_block(test_input: bytes, alignment: int, padding: int, expected: bytes) -> None:
    """Test the align_block function with various input parameters.

    Validates that the align_block function correctly aligns input data to the specified
    alignment boundary using the given padding value, and returns the expected result.

    :param test_input: Input bytes data to be aligned.
    :param alignment: Alignment boundary in bytes.
    :param padding: Padding value to use for alignment.
    :param expected: Expected aligned bytes result.
    """
    data = align_block(test_input, alignment, padding)
    assert isinstance(data, bytes)
    assert data == expected


@pytest.mark.parametrize(
    "test_input,alignment,expected",
    [
        # no change in empty data
        (b"", 4, b""),
        (b"", 1024, b""),
        # no change for alignment == 1
        (b"\x00", 1, b"\x00"),
        (b"\x00\x01\x02\x03", 2, b"\x00\x01\x02\x03"),
        (b"\x00\x01\x02\x03", 4, b"\x00\x01\x02\x03"),
        # align to 3
        (b"\x00", 3, 3),
        # align to 4
        (b"\x00", 4, 4),
        (b"\x00", 4, 4),
        # align to 16
        (b"\x02", 16, 16),
    ],
)
def test_align_block_fill_random(
    test_input: bytes, alignment: int, expected: Union[int, bytes]
) -> None:
    """Test the align_block_fill_random function with various inputs and alignments.

    This test verifies that align_block_fill_random produces the same results as
    align_block with random pattern filling. It checks both the length and content
    of the aligned data depending on the expected result type.

    :param test_input: Input bytes data to be aligned
    :param alignment: Alignment boundary in bytes
    :param expected: Expected result - either length (int) or exact bytes content
    :raises AssertionError: When alignment results don't match expectations
    """
    data1 = align_block_fill_random(test_input, alignment)
    data2 = align_block(test_input, alignment, BinaryPattern("rand"))
    assert isinstance(data1, bytes)
    if isinstance(expected, int):
        assert len(data1) == expected
        assert len(data2) == expected
    else:
        assert data1 == expected
        assert data2 == expected


def test_align_block_invalid_input() -> None:
    """Test invalid inputs for misc.align_block function.

    Validates that the align_block function properly raises exceptions when
    provided with invalid input parameters including None data, negative
    alignment values, and zero alignment values.

    :raises AssertionError: When data parameter is None.
    :raises SPSDKError: When alignment parameter is negative or zero.
    """
    with pytest.raises(AssertionError):
        align_block(None)  # type: ignore
    with pytest.raises(SPSDKError, match="Wrong alignment"):
        align_block(b"", -1)
    with pytest.raises(SPSDKError, match="Wrong alignment"):
        align_block(b"", 0)
    # with pytest.raises(SPSDKError, match="Wrong padding"):
    #     align_block(b"", 1, -2)
    # with pytest.raises(SPSDKError, match="Wrong padding"):
    #     align_block(b"", 1, 256)


@pytest.mark.parametrize(
    "test_input,length,padding,expected",
    [
        # extend empty data
        (b"", 4, 0, b"\x00\x00\x00\x00"),
        # no change for alignment == 1
        (b"\x00", 1, 0, b"\x00"),
        # align to 3
        (b"\x00", 3, 1, b"\x00\x01\x01"),
        # align to 4
        (b"\x00\x01\x02\x03", 4, 0, b"\x00\x01\x02\x03"),
        (b"\x00\x01\x02", 4, 0, b"\x00\x01\x02\x00"),
        (b"\x00\x01", 4, 255, b"\x00\x01\xff\xff"),
    ],
)
def test_add_padding(test_input: bytes, length: int, padding: int, expected: bytes) -> None:
    """Test the add_padding functionality from misc module.

    Validates that the extend_block function correctly pads input data to the specified
    length using the given padding value.

    :param test_input: Input bytes data to be padded.
    :param length: Target length for the padded data.
    :param padding: Padding value to use for extending the data.
    :param expected: Expected result after padding operation.
    """
    data = extend_block(test_input, length, padding)
    assert data == expected


def test_add_padding_invalid_input() -> None:
    """Test invalid inputs for extend_block function.

    Validates that extend_block function properly raises SPSDKError for various
    invalid input scenarios including negative length, length smaller than current
    block size, and invalid padding values.

    :raises SPSDKError: When extend_block is called with invalid parameters.
    """
    # negative length
    with pytest.raises(SPSDKError):
        extend_block(b"", -1)
    # length < current length
    with pytest.raises(SPSDKError):
        extend_block(b"\x00\x00", 1)
    # padding > 255
    with pytest.raises(SPSDKError):
        extend_block(b"\x00\x00", 1, 256)
    # padding < 0
    with pytest.raises(SPSDKError):
        extend_block(b"\x00\x00", 1, -1)


def test_find_first() -> None:
    """Test the find_first utility function.

    Validates that find_first correctly returns the first element from an iterable
    that matches the given predicate function. Tests various data types including
    lists, tuples, strings, and custom objects. Also verifies that None is returned
    when no matching element is found.
    """
    assert find_first([1, 2], lambda x: True) == 1
    assert find_first(["1", "2"], lambda x: True) == "1"
    assert find_first(["1", "2"], lambda x: x == "2") == "2"
    assert find_first((1, 2, 3, 4, 5), lambda x: True) == 1
    assert find_first((5, 4, 3, 2, 1, 0), lambda x: True) == 5
    assert find_first((5, 4, 3, 2, 1, 0), lambda x: x == "a") is None

    class TestClass:
        """Test utility class for SPSDK testing framework.

        This class provides a simple test fixture for unit testing scenarios,
        allowing tests to create instances with configurable state flags.
        """

        def __init__(self, first: bool = False):
            """Initialize the test class instance.

            :param first: Flag indicating if this is the first instance, defaults to False.
            """
            self.first = first

    assert find_first((TestClass(False), TestClass(False)), lambda x: x.first) is None
    assert find_first((TestClass(False), TestClass(True)), lambda x: x.first) is not None


def test_load_binary(data_dir: str) -> None:
    """Test loading binary files using load_binary and load_file.

    Verifies that both load_binary and load_file functions produce identical results
    when loading the same binary file, and validates the content matches expected
    byte sequence.

    :param data_dir: Directory path containing test data files.
    """
    data = load_binary(os.path.join(data_dir, "file.bin"))
    data2 = load_file(os.path.join(data_dir, "file.bin"), mode="rb")

    assert data == data2
    assert data == bytes(i for i in range(10))


def test_load_file(data_dir: str) -> None:
    """Test loading text file functionality.

    Verifies that the load_file function correctly reads and returns the content
    of text files, including files with special characters and Unicode content.

    :param data_dir: Directory path containing test data files
    """
    text = load_file(os.path.join(data_dir, "file.txt"))
    assert text == "Hello\nworld"

    text2 = load_file(os.path.join(data_dir, "file_special.txt"))
    assert text2 == "AÁBCČDĎEÉĚFGHChIÍJKLMNŇOÓPQRŘSŠTŤUÚŮVWXYÝZŽ\n"  # cspell: disable-line


def test_write_file(data_dir: str, tmpdir: Any) -> None:
    """Test writing data to files using write_file function.

    This test verifies that the write_file utility function correctly writes both
    binary and text data to files by comparing the written files with original
    reference files.

    :param data_dir: Directory path containing reference test files.
    :param tmpdir: Temporary directory path for writing test output files.
    """
    data = load_binary(os.path.join(data_dir, "file.bin"))
    text = load_file(os.path.join(data_dir, "file.txt"))

    write_file(data, os.path.join(tmpdir, "file.bin"), mode="wb")
    write_file(text, os.path.join(tmpdir, "file.txt"))

    assert filecmp.cmp(os.path.join(data_dir, "file.bin"), os.path.join(tmpdir, "file.bin"))
    assert filecmp.cmp(os.path.join(data_dir, "file.txt"), os.path.join(tmpdir, "file.txt"))


def test_file_file(data_dir: str) -> None:
    """Test file finding functionality in various directory scenarios.

    Tests the find_file utility function to ensure it correctly locates files
    when searching with relative paths from working directory and absolute paths.
    Verifies both search path functionality and direct file path resolution.

    :param data_dir: Base directory path containing test file structure
    """
    test_file = "file.txt"
    test_file_full_path = os.path.join(data_dir, "top_dir", "sub_dir1", test_file)
    test_file_full_path = test_file_full_path.replace("\\", "/")

    with use_working_directory(data_dir):
        assert find_file(test_file, search_paths=["top_dir/sub_dir1"])

    assert test_file_full_path == find_file(
        test_file, search_paths=[os.path.join(data_dir, "top_dir", "sub_dir1")]
    )
    assert test_file_full_path == find_file(
        os.path.join(data_dir, "top_dir", "sub_dir1", test_file)
    )


def test_find_file_invalid(data_dir: str) -> None:
    """Test find_file function with invalid file scenarios.

    This test verifies that find_file raises SPSDKError when attempting to find
    a non-existent file under different conditions: without using current working
    directory and with specified search paths.

    :param data_dir: Directory path to use as test data location
    :raises SPSDKError: When the specified file cannot be found
    """
    test_file = "file.txt"

    with use_working_directory(data_dir):
        with pytest.raises(SPSDKError):
            assert not find_file(test_file, use_cwd=False)
        with pytest.raises(SPSDKError):
            assert not find_file(test_file, use_cwd=False, search_paths=["top_dir"])


@pytest.mark.parametrize(
    "value,size,expected",
    [
        (0, 2, "0b00"),
        (0, 4, "0b0000"),
        (0, 10, "0b00_0000_0000"),
        (0, 8, "0x00"),
        (0, 16, "0x0000"),
        (0, 32, "0x0000_0000"),
        (0, 64, "0x0000_0000_0000_0000"),
    ],
)
def test_format_value(value: int, size: int, expected: str) -> None:
    """Test the format_value function with given parameters.

    Verifies that the format_value function correctly formats an integer value
    to a string representation with the specified size.

    :param value: Integer value to be formatted.
    :param size: Size parameter for formatting.
    :param expected: Expected string result after formatting.
    """
    assert format_value(value, size) == expected


def test_reg_long_reverse() -> None:
    """Test the reverse_bytes_in_longs function from Register Config utilities.

    Validates that the function correctly reverses byte order within 32-bit words
    of input data. Tests both forward and reverse operations, and verifies that
    invalid input lengths (not divisible by 4) raise appropriate exceptions.

    :raises SPSDKError: When input data length is not divisible by 4 bytes.
    """
    test_val = b"\x01\x02\x03\x04\x11\x12\x13\x14\x21\x22\x23\x24\x31\x32\x33\x34"
    test_val_ret = b"\x04\x03\x02\x01\x14\x13\x12\x11\x24\x23\x22\x21\x34\x33\x32\x31"

    assert reverse_bytes_in_longs(test_val) == test_val_ret
    assert reverse_bytes_in_longs(test_val_ret) == test_val

    test_val1 = b"\x01\x02\x03\x04\x11\x12"
    with pytest.raises(SPSDKError):
        reverse_bytes_in_longs(test_val1)


@pytest.mark.parametrize(
    "num, output, align_2_2n, byte_cnt, exception",
    [
        (0, 1, True, None, False),
        (1, 1, True, None, False),
        ((1 << 8) - 1, 1, True, None, False),
        ((1 << 8), 2, True, None, False),
        ((1 << 16) - 1, 2, True, None, False),
        ((1 << 16), 4, True, None, False),
        ((1 << 24) - 1, 4, True, None, False),
        ((1 << 24), 4, True, None, False),
        ((1 << 32) - 1, 4, True, None, False),
        ((1 << 32), 8, True, None, False),
        ((1 << 64) - 1, 8, True, None, False),
        ((1 << 64), 12, True, None, False),
        ((1 << 128) - 1, 16, True, None, False),
        ((1 << 128), 20, True, None, False),
        (0, 1, False, None, False),
        (1, 1, False, None, False),
        ((1 << 8) - 1, 1, False, None, False),
        ((1 << 8), 2, False, None, False),
        ((1 << 16) - 1, 2, False, None, False),
        ((1 << 16), 3, False, None, False),
        ((1 << 24) - 1, 3, False, None, False),
        ((1 << 24), 4, False, None, False),
        ((1 << 32) - 1, 4, False, None, False),
        ((1 << 32), 5, False, None, False),
        ((1 << 64) - 1, 8, False, None, False),
        ((1 << 64), 9, False, None, False),
        ((1 << 128) - 1, 16, False, None, False),
        ((1 << 128), 17, False, None, False),
        ((1 << 128), 20, True, 18, True),
    ],
)
def test_get_bytes_cnt(
    num: int, output: int, align_2_2n: bool, byte_cnt: Optional[int], exception: bool
) -> None:
    """Test get_bytes_cnt_of_int function with various parameters.

    This test function validates the behavior of get_bytes_cnt_of_int function
    with different input combinations, including both valid cases and exception scenarios.

    :param num: Integer number to get byte count for
    :param output: Expected output byte count
    :param align_2_2n: Whether to align to power of 2
    :param byte_cnt: Optional specific byte count requirement
    :param exception: Whether an exception is expected to be raised
    """
    if exception:
        with pytest.raises(SPSDKValueError):
            get_bytes_cnt_of_int(num, align_2_2n, byte_cnt=byte_cnt)
    else:
        assert output == get_bytes_cnt_of_int(num, align_2_2n, byte_cnt=byte_cnt)


@pytest.mark.parametrize(
    "value, res, exc",
    [
        (b"\x12", b"\x12", False),
        (b"\x12\x34", b"\x34\x12", False),
        (b"\x12\x34\x56", b"\x56\x34\x12", True),
        (b"\x12\x34\x56\x78", b"\x78\x56\x34\x12", False),
        (b"\x12\x34\x56\x78\x12\x34\x56\x78", b"\x78\x56\x34\x12\x78\x56\x34\x12", False),
        (b"\x12\x34\x56\x78\x12\x34\x56", b"\x78\x56\x34\x12\x78\x56\x34", True),
    ],
)
def test_change_endianness(value: bytes, res: bytes, exc: bool) -> None:
    """Test the change_endianness function with various input scenarios.

    Validates that the change_endianness function correctly converts byte order
    for valid inputs and raises appropriate exceptions for invalid inputs.

    :param value: Input bytes to test endianness conversion on.
    :param res: Expected result bytes after endianness change.
    :param exc: Flag indicating whether an exception should be raised.
    """
    if not exc:
        assert res == change_endianness(value)
    else:
        with pytest.raises(SPSDKError):
            change_endianness(value)


@pytest.mark.parametrize(
    "value, res, exc",
    [
        (0, 0, False),
        ("0", 0, False),
        ("-1", -1, True),
        ("0xffff", 65535, False),
        ("0xffffu", 65535, False),
        ("0xffffU", 65535, False),
        ("0xfffful", 65535, False),
        ("0xffffUL", 65535, False),
        ("ffff", 65535, True),
        ("0xff_ff", 65535, False),
        ("ff_ff", 65535, True),
        ("0b111_1", 15, False),
        (b"\xff\x00", 65280, False),
        (bytearray(b"\xff\x00"), 65280, False),
        ("InvalidValue", 0, True),
    ],
)
def test_value_to_int(value: Union[int, str, bytes, bytearray], res: int, exc: bool) -> None:
    """Test the value_to_int function with various input types and expected outcomes.

    This test function validates the value_to_int function by testing it with different
    input values and verifying either successful conversion or proper exception handling.

    :param value: Input value to be converted to integer (int, str, bytes, or bytearray).
    :param res: Expected integer result when conversion should succeed.
    :param exc: Flag indicating whether an exception is expected during conversion.
    """
    if not exc:
        assert res == value_to_int(value)
    else:
        with pytest.raises(SPSDKError):
            value_to_int(value)


@pytest.mark.parametrize(
    "value, res, exc",
    [
        (0, b"\x00", False),
        ("0", b"\x00", False),
        ("-1", b"\xff", True),
        ("0xffff", b"\xff\xff", False),
        ("ffff", b"\xff\xff", True),
        ("0xff_ff", b"\xff\xff", False),
        ("0b111_1", b"\x0f", False),
        ("ff_ff", b"\xff\xff", True),
        (b"\xff\x00", b"\xff\x00", False),
        (bytearray(b"\xff\x00"), b"\xff\x00", False),
        ("InvalidValue", 0, True),
    ],
)
def test_value_to_bytes(
    value: Union[int, str, bytes, bytearray], res: Union[bytes, int], exc: bool
) -> None:
    """Test the value_to_bytes function with various input types and expected outcomes.

    This test function validates the behavior of value_to_bytes function by checking
    both successful conversions and error conditions based on the exc parameter.

    :param value: Input value to be converted to bytes (int, str, bytes, or bytearray).
    :param res: Expected result - either the expected bytes output or error indicator.
    :param exc: Flag indicating whether an exception is expected during conversion.
    :raises SPSDKError: When exc is True and the conversion should fail.
    """
    if not exc:
        assert res == value_to_bytes(value)
    else:
        with pytest.raises(SPSDKError):
            value_to_bytes(value)


@pytest.mark.parametrize(
    "value, res, exc",
    [
        (0, False, False),
        (False, False, False),
        (None, False, False),
        ("False", False, False),
        (1, True, False),
        (True, True, False),
        ("True", True, False),
        ("T", True, False),
        (b"\x20", True, False),
    ],
)
def test_value_to_bool(value: Optional[Union[int, bool, str]], res: bool, exc: bool) -> None:
    """Test the value_to_bool function with various input types and expected outcomes.

    This test function validates the behavior of value_to_bool function by checking
    both successful conversions and exception cases based on the provided parameters.

    :param value: Input value to be converted to boolean (int, bool, str, or None).
    :param res: Expected boolean result when conversion should succeed.
    :param exc: Flag indicating whether an exception should be raised during conversion.
    """
    if not exc:
        assert res == value_to_bool(value)
    else:
        with pytest.raises(SPSDKError):
            value_to_bool(value)


def test_timeout_basic() -> None:
    """Test basic functionality of Timeout class.

    Verifies that a newly created Timeout instance does not overflow initially,
    and that it properly raises SPSDKTimeoutError when the timeout period expires
    and overflow checking is enforced.

    :raises SPSDKTimeoutError: When timeout period has expired and overflow check is enforced.
    """
    timeout = Timeout(50, "ms")
    assert not timeout.overflow()
    time.sleep(0.1)
    with pytest.raises(SPSDKTimeoutError):
        timeout.overflow(True)


def test_timeout_invalid_unit() -> None:
    """Test that Timeout class raises SPSDKValueError for invalid time units.

    Verifies that creating a Timeout instance with an unsupported time unit
    (like "day") properly raises SPSDKValueError exception.

    :raises SPSDKValueError: When invalid time unit is provided to Timeout constructor.
    """
    with pytest.raises(SPSDKValueError):
        Timeout(100, "day")


def test_timeout_get_time() -> None:
    """Test timeout functionality including time tracking and error handling.

    This test verifies that the Timeout class correctly tracks consumed and remaining time,
    handles timeout expiration, and raises appropriate exceptions when timeouts occur.
    The test creates a 50ms timeout, verifies initial time relationships, waits for
    timeout expiration, and validates error conditions.
    """
    timeout = Timeout(50, "ms")
    assert timeout.get_consumed_time() < timeout.get_rest_time()
    assert timeout.get_consumed_time_ms() < timeout.get_rest_time_ms()
    time.sleep(0.1)
    assert timeout.get_rest_time() < 0
    assert timeout.get_rest_time_ms() < 0
    with pytest.raises(SPSDKTimeoutError):
        timeout.get_rest_time(True)
    with pytest.raises(SPSDKTimeoutError):
        timeout.get_rest_time_ms(True)


@pytest.mark.parametrize(
    "input_value, use_kibibyte, expected",
    [
        (0, False, "0 B"),
        (0, True, "0 B"),
        (1568, True, "1.5 kiB"),
        (1568, False, "1.6 kB"),
        (177768, True, "173.6 kiB"),
        (157768, False, "157.8 kB"),
        (15565654654654654654668, False, "15565.7 PB"),
        (15565654654654654654668, True, "13501.1 PiB"),
    ],
)
def test_size_format(input_value: int, use_kibibyte: bool, expected: str) -> None:
    """Test size formatting function with various inputs and options.

    Verifies that the size_fmt function correctly formats byte values into
    human-readable strings with optional kibibyte units.

    :param input_value: The byte value to be formatted.
    :param use_kibibyte: Whether to use kibibyte (1024-based) or kilobyte (1000-based) units.
    :param expected: The expected formatted string output.
    """
    assert size_fmt(input_value, use_kibibyte) == expected


def test_swap16_invalid() -> None:
    """Test that swap16 function raises error for invalid input values.

    Verifies that the swap16 function properly validates input and raises
    SPSDKError when given a number that exceeds the valid 16-bit range.

    :raises SPSDKError: When input number is outside valid 16-bit range.
    """
    with pytest.raises(SPSDKError, match="Incorrect number to be swapped"):
        swap16(0xFFFFA)


@pytest.mark.parametrize(
    "input_value, bits_cnt, expected",
    [
        (0, 32, 0),
        (1, 8, 0b10000000),
        (0x12345678, 32, 0x1E6A2C48),
        (1, 64, 1 << 63),
    ],
)
def test_reverse_bits(input_value: int, bits_cnt: int, expected: int) -> None:
    """Test reverse_bits function with given parameters.

    Verifies that the reverse_bits function correctly reverses the specified number
    of bits in the input value and returns the expected result.

    :param input_value: The integer value whose bits should be reversed.
    :param bits_cnt: The number of bits to consider for reversal.
    :param expected: The expected result after bit reversal.
    """
    assert reverse_bits(input_value, bits_cnt) == expected


def test_load_secret(data_dir: str) -> None:
    """Test the load_secret function with various input types.

    Tests loading secrets from file paths, direct text input, and environment
    variables. Verifies that the function correctly handles file-based secrets,
    plain text secrets, and environment variable references both as direct values
    and as file paths.

    :param data_dir: Directory path containing test data files including secret.txt
    """
    file_with_secret = os.path.join(data_dir, "secret.txt")
    assert load_secret(file_with_secret) == "secret text"
    assert load_secret("secret text") == "secret text"
    load_secret("$TEST_VAR")
    with patch.dict("os.environ", {"TEST_VAR": "secret text"}):
        assert load_secret("$TEST_VAR") == "secret text"
    with patch.dict("os.environ", {"TEST_VAR": file_with_secret}):
        assert load_secret("$TEST_VAR") == "secret text"
