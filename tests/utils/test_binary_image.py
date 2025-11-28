#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK BinaryImage utility class.

This module contains comprehensive unit tests for the BinaryImage class and related
functionality from spsdk.utils.binary_image, covering binary image manipulation,
file format support, and validation operations.
"""

import os
from typing import Any, Optional

import pytest

from spsdk.exceptions import SPSDKError, SPSDKValueError
from spsdk.utils.binary_image import BinaryImage, BinaryPattern


def test_binary_image_sort_sub_images() -> None:
    """Test binary image sub-image sorting functionality.

    Validates that sub-images within a BinaryImage are properly sorted by offset
    when added in non-sequential order. Creates a main binary image with zero
    pattern and adds three sub-images at different offsets (0x2, 0x4, 0x6) in
    non-sequential order, then verifies the final exported binary has the correct
    sorted structure.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    image.validate()

    assert image.size == 8
    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"


def test_binary_image_join_sub_images() -> None:
    """Test joining sub-images functionality in BinaryImage class.

    This test verifies that the BinaryImage.join_images() method correctly merges
    sub-images into the main binary data and clears the sub_images list. It creates
    a main image with zero pattern and adds three sub-images at different offsets,
    then validates the joining operation produces the expected binary output.

    :raises AssertionError: If the binary output doesn't match expected values or sub-images aren't properly joined.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    image.validate()

    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"

    assert len(image.sub_images) == 3

    image.join_images()

    assert len(image.sub_images) == 0

    assert image.binary == b"\x00\x00\x02\x00\x04\x00\x06\x00"
    assert image.export() == b"\x00\x00\x02\x00\x04\x00\x06\x00"


def test_binary_image_pattern() -> None:
    """Test BinaryPattern class functionality with different pattern types.

    Validates that BinaryPattern correctly generates binary data for various
    pattern types including zeros, ones, random, and incremental patterns.
    Ensures proper block size handling and expected output formats.

    :raises AssertionError: If any pattern generates unexpected binary data.
    """
    assert BinaryPattern("zeros").get_block(4) == b"\x00\x00\x00\x00"
    assert BinaryPattern("ones").get_block(4) == b"\xff\xff\xff\xff"
    assert len(BinaryPattern("rand").get_block(4)) == 4
    assert BinaryPattern("inc").get_block(4) == b"\x00\x01\x02\x03"


def test_binary_image_invalid_pattern() -> None:
    """Test that BinaryPattern raises SPSDKValueError for invalid pattern strings.

    Verifies that the BinaryPattern constructor properly validates input patterns
    and raises the appropriate exception when given an invalid pattern string.

    :raises SPSDKValueError: When an invalid pattern string is provided to BinaryPattern constructor.
    """
    with pytest.raises(SPSDKValueError):
        BinaryPattern("invalid")


def test_binary_image_draw() -> None:
    """Test the draw functionality of the BinaryImage class.

    This test verifies that the BinaryImage.draw() method correctly generates
    visual representations with and without color formatting. It creates a main
    binary image with embedded sub-images at specific offsets and validates
    that ANSI color codes are present in colored output and absent in non-colored output.

    :raises AssertionError: If the draw method doesn't produce expected color formatting behavior.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x1, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))
    image_0x6 = BinaryImage(name="0x6", offset=0x6, size=0x1, pattern=BinaryPattern("0x6"))

    image.add_image(image_0x2)
    image.add_image(image_0x6)
    image.add_image(image_0x4)

    assert "\x1b[" in image.draw()
    assert "\x1b[" not in image.draw(no_color=True)


def test_binary_image_draw_invalid() -> None:
    """Test BinaryImage draw method with overlapping regions.

    This test verifies that the draw method properly handles and visualizes
    overlapping binary images by checking for the presence of error color codes
    in the output. The test creates a main image with two overlapping sub-images
    and confirms that the visualization indicates the conflict with red coloring.

    :raises AssertionError: If the draw output doesn't contain the expected error color code.
    """
    image = BinaryImage(name="main", size=8, pattern=BinaryPattern("zeros"))

    image_0x2 = BinaryImage(name="0x2", offset=0x2, size=0x4, pattern=BinaryPattern("0x2"))
    image_0x4 = BinaryImage(name="0x4", offset=0x4, size=0x1, pattern=BinaryPattern("0x4"))

    image.add_image(image_0x2)
    image.add_image(image_0x4)

    assert "\x1b[31m" in image.draw()


@pytest.mark.parametrize(
    "path",
    [
        ("images/image.bin"),
        ("images/image.hex"),
        ("images/image.s19"),
        ("images/image.srec"),
    ],
)
def test_load_binary_image(path: str, data_dir: str) -> None:
    """Test loading a binary image from file path.

    Verifies that a binary image can be successfully loaded from the specified file path
    and validates the loaded binary image properties including type and non-zero length.

    :param path: Relative path to the binary image file.
    :param data_dir: Directory path containing test data files.
    """
    binary = BinaryImage.load_binary_image(os.path.join(data_dir, path))
    assert binary
    assert isinstance(binary, BinaryImage)
    assert len(binary) > 0


@pytest.mark.parametrize(
    "path,execution_start_address",
    [
        ("images/image.bin", None),
        ("images/image.hex", "0x6000231D"),
        ("images/image.s19", "0x8E37D"),
        ("images/image.srec", "0x8001159"),
    ],
)
def test_execution_start_address(
    path: str, execution_start_address: Optional[str], data_dir: str
) -> None:
    """Test execution start address of a binary image.

    Loads a binary image from the specified path and verifies that its execution
    start address matches the expected value. If no expected address is provided,
    verifies that the execution start address is None.

    :param path: Relative path to the binary image file within the data directory.
    :param execution_start_address: Expected execution start address
        as hexadecimal string, or None if no address expected.
    :param data_dir: Base directory path containing test data files.
    """
    binary = BinaryImage.load_binary_image(os.path.join(data_dir, path))
    if execution_start_address is not None:
        assert binary.execution_start_address == int(execution_start_address, 16)
    else:
        assert binary.execution_start_address is None


@pytest.mark.parametrize(
    "path,error_msg",
    [
        (
            "images/image_corrupted.s19",
            (
                "Error loading file: expected crc 'D3' in record "
                "S21407F41001020100010600000200000000000000D4, but got 'D4'"
            ),
        )
    ],
)
def test_load_binary_image_invalid_s19(path: str, error_msg: str, data_dir: str) -> None:
    """Test loading binary image with invalid S19 file format.

    This test verifies that BinaryImage.load_binary_image properly raises
    SPSDKError when attempting to load an invalid S19 file with the expected
    error message.

    :param path: Relative path to the invalid S19 file in the data directory.
    :param error_msg: Expected error message pattern to match in the raised exception.
    :param data_dir: Absolute path to the test data directory.
    :raises SPSDKError: Always raised due to invalid S19 file format.
    """
    with pytest.raises(SPSDKError, match=error_msg):
        BinaryImage.load_binary_image(os.path.join(data_dir, path))


def test_load_binary_image_invalid(data_dir: str) -> None:
    """Test loading binary image with invalid file path.

    Verifies that BinaryImage.load_binary_image raises SPSDKError when attempting
    to load from a non-existent or invalid file path.

    :param data_dir: Directory path containing test data files.
    """
    with pytest.raises(SPSDKError):
        BinaryImage.load_binary_image(os.path.join(data_dir, "invalid_file"))


def test_binary_image_load_elf(data_dir: str) -> None:
    """Test loading and merging of ELF binary image files.

    This test verifies the correct loading of a problematic ELF file and validates
    its properties including size and offset. It also tests the ability to merge
    multiple binary images by adding an S19 format image to the loaded ELF image.

    :param data_dir: Path to the directory containing test data files.
    """
    binary = BinaryImage.load_binary_image(os.path.join(data_dir, "images/image_0x80002000.elf"))
    assert binary
    assert isinstance(binary, BinaryImage)
    assert len(binary) > 0
    assert binary.size == 19368
    assert binary.offset == 0x8000_2000
    binary.add_image(BinaryImage.load_binary_image(os.path.join(data_dir, "images/image.s19")))
    assert binary.size == 582818


def test_execution_address_is_preserved_in_exported_image(tmpdir: Any, data_dir: str) -> None:
    """Test that execution address is preserved when exporting and reloading binary images.

    This test verifies that the execution start address remains intact when a binary
    image is exported to a different format (S19) and then reloaded. It ensures
    data integrity during format conversion operations.

    :param tmpdir: Temporary directory for test file operations.
    :param data_dir: Directory containing test data files.
    """
    elf_binary = BinaryImage.load_binary_image(
        os.path.join(data_dir, "images/image_0x80002000.elf")
    )
    assert elf_binary.execution_start_address == 0x80002305
    s19_path = os.path.join(tmpdir, "image_0x80002000.s19")
    elf_binary.save_binary_image(s19_path, "S19")
    s19_binary = BinaryImage.load_binary_image(s19_path)
    assert s19_binary.execution_start_address == 0x80002305
