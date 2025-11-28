#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK application utilities test module.

This module contains comprehensive test cases for the SPSDK application utilities
functionality, including string processing, data formatting, file operations,
hexadecimal data parsing, error handling, and configuration management.
"""

from typing import Optional

import pytest

from spsdk.apps.utils import utils
from spsdk.apps.utils.utils import catch_spsdk_error, make_table_from_items
from spsdk.exceptions import SPSDKError
from spsdk.mboot.exceptions import McuBootConnectionError
from spsdk.utils.misc import load_configuration, use_working_directory


def test_split_string() -> None:
    """Test the _split_string utility function.

    Verifies that the _split_string function correctly splits a string into chunks
    of specified length, with the last chunk containing any remaining characters.
    """
    assert ["12", "34", "5"] == utils._split_string("12345", length=2)
    assert ["123", "123"] == utils._split_string("123123", length=3)


def test_format_data() -> None:
    """Test format_raw_data utility function with different line lengths.

    Verifies that the format_raw_data function correctly formats byte data
    into hexadecimal string representation with specified line lengths.
    Tests both 8-byte and 16-byte line length configurations.
    """
    data = bytes(range(20))
    expect_8 = "00 01 02 03 04 05 06 07\n08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
    assert expect_8 == utils.format_raw_data(data, use_hexdump=False, line_length=8)
    expect_16 = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
    assert expect_16 == utils.format_raw_data(data, use_hexdump=False, line_length=16)


@pytest.mark.parametrize(
    "input_param,exp_path,exp_size",
    [("path", "path", -1), ("path,10", "path", 10), ("path,0x20", "path", 0x20)],
)
def test_file_size_composite(input_param: str, exp_path: str, exp_size: int) -> None:
    """Test file size composite parsing functionality.

    Validates that the parse_file_and_size utility function correctly extracts
    both file path and size from a composite input parameter string.

    :param input_param: Input string containing file path and size information
    :param exp_path: Expected file path to be extracted
    :param exp_size: Expected size value to be extracted
    """
    path, size = utils.parse_file_and_size(input_param)
    assert path == exp_path
    assert size == exp_size


@pytest.mark.parametrize(
    "input_hex_data,output_bytes",
    [
        ("{{11223344}}", b"\x11\x22\x33\x44"),
        ("{{11 22 33 44}}", b"\x11\x22\x33\x44"),
        (" { { 11    22 33 44}}", b"\x11\x22\x33\x44"),
        ("{{bcd}}", b"\xbc\x0d"),
        ("[[bcd]]", b"\xbc\x0d"),
        ("[[ 01 02 ]]", b"\x01\x02"),
    ],
)
def test_parse_hex_data(input_hex_data: str, output_bytes: bytes) -> None:
    """Test parsing of hexadecimal string data into bytes.

    Verifies that the utils.parse_hex_data function correctly converts
    hexadecimal string input into the expected byte representation.

    :param input_hex_data: Hexadecimal string to be parsed
    :param output_bytes: Expected byte output after parsing
    """
    parsed_data = utils.parse_hex_data(input_hex_data)
    assert parsed_data == output_bytes


@pytest.mark.parametrize(
    "input_hex_data",
    [
        ("{ { } }"),
        ("11223344"),
        ("{{11223344"),
        ("11223344}}"),
        ("{11223344}"),
        ("{{11 xa}}"),
        ("{{ab zz}}"),
    ],
)
def test_parse_hex_data_error(input_hex_data: str) -> None:
    """Test that parse_hex_data raises SPSDKError for invalid input.

    Verifies that the parse_hex_data utility function properly raises SPSDKError
    when provided with malformed or invalid hexadecimal data strings.

    :param input_hex_data: Invalid hexadecimal data string to test error handling.
    """
    with pytest.raises(SPSDKError):
        utils.parse_hex_data(input_hex_data)


@catch_spsdk_error
def function_under_test(to_raise: Optional[Exception] = None) -> int:
    """Test utility function that optionally raises an exception.

    This function is designed for testing purposes to simulate both successful
    execution and exception scenarios in unit tests.

    :param to_raise: Optional exception to raise. If None, function returns normally.
    :return: Returns 0 when no exception is specified.
    :raises Exception: Raises the provided exception if to_raise is not None.
    """
    if to_raise is None:
        return 0
    raise to_raise


def test_catch_spsdk_error() -> None:
    """Test SPSDK error handling and exit code behavior.

    Verifies that the function_under_test properly handles different exception types
    and returns appropriate exit codes. Tests SPSDK-specific exceptions (AssertionError,
    McuBootConnectionError) which should exit with code 2, generic exceptions
    (IndexError) which should exit with code 3, and successful execution with None
    input which should return code 0.

    :raises SystemExit: When function_under_test is called with exception instances.
    """
    with pytest.raises(SystemExit) as exc:
        function_under_test(AssertionError())
    assert exc.value.code == 2

    with pytest.raises(SystemExit) as exc_2:
        function_under_test(McuBootConnectionError())
    assert exc_2.value.code == 2

    with pytest.raises(SystemExit) as exc_3:
        function_under_test(IndexError())
    assert exc_3.value.code == 3

    assert function_under_test(None) == 0


@pytest.mark.parametrize("file_name", ["certgen_config.yaml", "test_config.json"])
def test_load_configuration(data_dir: str, file_name: str) -> None:
    """Test loading configuration from a file in the specified directory.

    This test verifies that the load_configuration function can successfully
    load a configuration file and return it as a dictionary object.

    :param data_dir: Directory path containing the configuration file.
    :param file_name: Name of the configuration file to load.
    """
    with use_working_directory(data_dir):
        result = load_configuration(file_name)
        assert isinstance(result, dict)


@pytest.mark.parametrize("file_name", ["zeros.bin", "invalid_file.json"])
def test_load_configuration_invalid_file(data_dir: str, file_name: str) -> None:
    """Test loading configuration with invalid file.

    This test verifies that load_configuration properly raises SPSDKError
    when attempting to load a configuration from an invalid or non-existent file.

    :param data_dir: Directory path to use as working directory for the test.
    :param file_name: Name of the invalid configuration file to attempt loading.
    :raises SPSDKError: Expected exception when loading invalid configuration file.
    """
    with use_working_directory(data_dir):
        with pytest.raises(SPSDKError):
            load_configuration(file_name)


def test_make_table_from_items() -> None:
    """Test the make_table_from_items function with various parameters.

    This test verifies that the make_table_from_items function correctly formats
    a list of items into table rows with specified row and column widths.
    The test checks that items are properly distributed across rows and that
    each item is formatted with the correct column width.
    """
    rows = make_table_from_items(["A", "B", "C", "D", "E"], row_width=10, column_width=5)
    assert len(rows) == 3
    assert rows[0] == "A    B  "
    assert rows[1] == "C    D  "
    assert rows[2] == "E  "
