#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK BLHost utilities test module.

This module contains comprehensive test cases for BLHost helper utilities,
focusing on parsing functions and data validation within the SPSDK framework.
The tests validate parsing of various BLHost command parameters including
property tags, key types, image files, and trust provisioning configurations.
"""

import os

import pytest

from spsdk.apps.blhost_helper import (
    parse_key_prov_key_type,
    parse_property_tag,
    parse_trust_prov_key_type,
    parse_trust_prov_oem_key_type,
    parse_trust_prov_wrapping_key_type,
)
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.family import FamilyRevision


@pytest.mark.parametrize(
    "parse_input,expected",
    [
        ("1", 1),
        ("0xa", 10),
        ("0b100", 4),
        ("list-properties", 0),
        ("target-version", 24),
        ("abc", 0xFF),
        ("012", 12),
        ("some-nonsense", 0xFF),
    ],
)
def test_parse_property_tag(parse_input: str, expected: int) -> None:
    """Test parsing of property tag from string input.

    Verifies that the parse_property_tag function correctly converts
    a string representation of a property tag to its expected integer value.

    :param parse_input: String representation of the property tag to parse.
    :param expected: Expected integer value after parsing the input string.
    """
    actual = parse_property_tag(parse_input)
    assert actual == expected


@pytest.mark.parametrize(
    "parse_input,family,expected",
    [
        ("verify-erase", "kw45b41z8", 10),
        ("verify-erase", "k32w148", 10),
        ("current-version", "kw45b41z8", 1),
        ("current-version", "k32w148", 1),
    ],
)
def test_parse_property_tag_override(parse_input: str, family: str, expected: int) -> None:
    """Test parsing of property tag with family-specific override.

    Verifies that the parse_property_tag function correctly handles property tag
    parsing when a family-specific override is provided, ensuring the returned
    value matches the expected result.

    :param parse_input: Property tag string to be parsed.
    :param family: Target MCU family name for family-specific parsing.
    :param expected: Expected integer value after parsing the property tag.
    """
    actual = parse_property_tag(parse_input, FamilyRevision(family))
    assert actual == expected


@pytest.mark.parametrize(
    "parse_input, expected",
    [
        ("1", 1),
        ("0xa", 10),
        ("0b100", 4),
        ("abc", 0xFF),
        ("012", 12),
        ("some-nonsense", 0xFF),
        ("sbkek", 3),
        ("UDS", 12),
    ],
)
def test_parse_key_prov_key_type(parse_input: str, expected: int) -> None:
    """Test parsing of key provisioning key type input strings.

    Verifies that the parse_key_prov_key_type function correctly converts
    string representations of key types to their corresponding integer values.

    :param parse_input: String representation of the key type to be parsed.
    :param expected: Expected integer value that should result from parsing the input.
    """
    actual = parse_key_prov_key_type(parse_input)
    assert actual == expected


@pytest.mark.parametrize(
    "path, segment_info_list",
    [
        (
            "evkmimxrt685_led_blinky_ext_flash.srec",
            [(0x08001000, 0x54EC)],
        ),
        (
            "sdk20-app.s19",
            [
                (0x7F400, 512),
                (0x80000, 360),
                (0x80180, 58146),
            ],
        ),
        (
            "iled_blinky_ide_1060.hex",
            [(0x60002000, 0x32CC)],
        ),
    ],
)
def test_parse_image_file(
    path: str, segment_info_list: list[tuple[int, int]], data_dir: str
) -> None:
    """Test parsing of binary image file against expected segment information.

    Loads a binary image file and validates that the parsed segments match
    the expected segment information including addresses and sizes.

    :param path: Relative path to the binary image file within data directory.
    :param segment_info_list: List of tuples containing expected (address, size) pairs for each segment.
    :param data_dir: Absolute path to the data directory containing test files.
    :raises AssertionError: When parsed segments don't match expected segment information.
    """
    result = BinaryImage.load_binary_image(os.path.join(data_dir, path))
    assert len(result.sub_images) == len(segment_info_list)
    for current, ref in zip(result.sub_images, segment_info_list):
        assert current.absolute_address == ref[0]
        assert len(current) == ref[1]


@pytest.mark.parametrize(
    "path, aligned_sizes",
    [
        ("evkmimxrt685_led_blinky_ext_flash.srec", [(0x08001000, 0x5800)]),
        (
            "sdk20-app.s19",
            [
                (0x7F400, 0x400),
                (0x80000, 0x400),
                (0x80000, 0xE800),
            ],
        ),
        (
            "iled_blinky_ide_1060.hex",
            [(0x60002000, 0x3400)],
        ),
    ],
)
def test_parse_image_file_aligned_sizes(
    path: str, aligned_sizes: list[tuple[int, int]], data_dir: str
) -> None:
    """Test that binary image file parsing produces segments with expected aligned sizes.

    Loads a binary image file and verifies that each sub-image segment has the
    correct aligned start address and length when aligned to 1024-byte boundaries.

    :param path: Relative path to the binary image file within the data directory.
    :param aligned_sizes: List of tuples containing expected (aligned_start, aligned_length) pairs for each segment.
    :param data_dir: Base directory path containing test data files.
    """
    result = BinaryImage.load_binary_image(os.path.join(data_dir, path))
    assert len(result.sub_images) == len(aligned_sizes)
    for segment, expected in zip(result.sub_images, aligned_sizes):
        assert segment.aligned_start(1024) == expected[0]
        assert segment.aligned_length(1024) == expected[1]


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        ("MFWISK", 50085),
        ("0xC3A5", 50085),
        ("0xc3a5", 50085),
        ("MFWENCK", 42435),
        ("0xA5C3", 42435),
        ("GENSIGNK", 23100),
        ("0x5A3C", 23100),
        ("GETCUSTMKSK", 15450),
        ("0x3C5A", 15450),
        ("ENCKEY", 15525),
        ("0x3CA5", 15525),
        ("0x3ca5", 15525),
    ],
)
def test_parse_tp_prov_oem_key_type(input_value: str, expected_output: int) -> None:
    """Test parsing of trust provisioning OEM key type values.

    Verifies that the parse_trust_prov_oem_key_type function correctly converts
    string input values to their corresponding integer representations.

    :param input_value: String representation of the OEM key type to parse.
    :param expected_output: Expected integer value after parsing.
    """
    actual = parse_trust_prov_oem_key_type(input_value)
    assert actual == expected_output


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        ("1", 1),
        ("CKDFK", 1),
        ("2", 2),
        ("HKDFK", 2),
        ("3", 3),
        ("HMACK", 3),
        ("4", 4),
        ("CMACK", 4),
        ("5", 5),
        ("AESK", 5),
        ("6", 6),
        ("KUOK", 6),
    ],
)
def test_parse_tp_prov_key_type(input_value: str, expected_output: int) -> None:
    """Test parsing of trust provisioning key type values.

    Verifies that the parse_trust_prov_key_type function correctly converts
    string input values to their corresponding integer representations.

    :param input_value: String representation of the trust provisioning key type to parse.
    :param expected_output: Expected integer value that should be returned by the parser.
    """
    actual = parse_trust_prov_key_type(input_value)
    assert actual == expected_output


@pytest.mark.parametrize(
    "input_value, expected_output",
    [
        ("0x10", 16),
        ("INT_SK", 16),
        ("0x11", 17),
        ("EXT_SK", 17),
    ],
)
def test_parse_tp_prov_wrapping_key_type(input_value: str, expected_output: int) -> None:
    """Test parsing of trust provisioning wrapping key type values.

    Verifies that the parse_trust_prov_wrapping_key_type function correctly
    converts string input values to their corresponding integer representations.

    :param input_value: String representation of the wrapping key type to parse.
    :param expected_output: Expected integer value after parsing.
    """
    actual = parse_trust_prov_wrapping_key_type(input_value)
    assert actual == expected_output
