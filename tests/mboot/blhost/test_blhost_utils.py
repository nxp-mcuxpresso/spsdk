#!/usr/bin/env python
#
# Copyright 2021-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK BLHost utilities test module.

This module contains comprehensive test cases for BLHost helper utilities,
focusing on parsing functions and data validation within the SPSDK framework.
The tests validate parsing of various BLHost command parameters including
property tags, key types, image files, and trust provisioning configurations.
"""

import os
from unittest.mock import MagicMock

import pytest

from spsdk.apps.blhost_helper import (
    ASSUMED_FLASH_THROUGHPUT,
    DEFAULT_ERASE_ALIGNMENT,
    MAX_ERASE_PROGRESS_STEPS,
    MIN_ERASE_PROGRESS_LENGTH,
    estimate_flash_timeout,
    flash_erase_region_with_progress,
    flash_operation_timeout,
    get_erase_alignment,
    get_erase_chunk_size,
    parse_key_prov_key_type,
    parse_property_tag,
    parse_trust_prov_key_type,
    parse_trust_prov_oem_key_type,
    parse_trust_prov_wrapping_key_type,
)
from spsdk.exceptions import SPSDKError
from spsdk.mboot.memories import ExtMemPropTags
from spsdk.mboot.properties import PropertyTag
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


def test_get_erase_alignment_internal_flash() -> None:
    """Test that the internal flash sector size reported by the target is used."""
    mboot = MagicMock()
    mboot.get_property.return_value = [0x8000]

    assert get_erase_alignment(mboot, mem_id=0) == 0x8000
    mboot.get_property.assert_called_once_with(PropertyTag.FLASH_SECTOR_SIZE)


def test_get_erase_alignment_external_memory() -> None:
    """Test that the external memory sector size reported by the target is used."""
    mboot = MagicMock()
    # raw values: [available tags, start address, size in kB, page size, sector size, block size]
    mboot.get_property.return_value = [ExtMemPropTags.SECTOR_SIZE.tag, 0, 0, 0, 0x10000, 0]

    assert get_erase_alignment(mboot, mem_id=9) == 0x10000
    mboot.get_property.assert_called_once_with(PropertyTag.EXTERNAL_MEMORY_ATTRIBUTES, index=9)


@pytest.mark.parametrize(
    "mem_id, property_result",
    [
        (0, None),
        (0, []),
        (9, None),
        # external memory not reporting the sector size
        (9, [ExtMemPropTags.START_ADDRESS.tag, 0x60000000, 0, 0, 0, 0]),
    ],
)
def test_get_erase_alignment_fallback(mem_id: int, property_result: list[int] | None) -> None:
    """Test the fallback alignment when the target does not report the erase block size."""
    mboot = MagicMock()
    mboot.get_property.return_value = property_result

    assert get_erase_alignment(mboot, mem_id=mem_id) == DEFAULT_ERASE_ALIGNMENT


@pytest.mark.parametrize("mem_id", [0, 9])
def test_get_erase_alignment_property_error(mem_id: int) -> None:
    """Test the fallback alignment when the property query fails."""
    mboot = MagicMock()
    mboot.get_property.side_effect = SPSDKError("Unknown property")

    assert get_erase_alignment(mboot, mem_id=mem_id) == DEFAULT_ERASE_ALIGNMENT


@pytest.mark.parametrize(
    "length, base_timeout, expected",
    [
        # small images keep the base timeout
        (0, 5000, 5000),
        (1024, 5000, 5000),
        (ASSUMED_FLASH_THROUGHPUT, 5000, 5000),
        # large images scale the timeout up
        (ASSUMED_FLASH_THROUGHPUT * 10, 5000, 10000),
        (ASSUMED_FLASH_THROUGHPUT * 60, 5000, 60000),
        # an explicitly raised base timeout is never lowered
        (ASSUMED_FLASH_THROUGHPUT * 10, 60000, 60000),
    ],
)
def test_estimate_flash_timeout(length: int, base_timeout: int, expected: int) -> None:
    """Test the automatic timeout estimation based on the processed data length."""
    assert estimate_flash_timeout(length, base_timeout) == expected


def test_flash_operation_timeout_increases_and_restores() -> None:
    """Test that the device timeout is temporarily increased and then restored."""
    mboot = MagicMock()
    mboot.interface.device.timeout = 5000
    length = ASSUMED_FLASH_THROUGHPUT * 60

    with flash_operation_timeout(mboot, length):
        assert mboot.interface.device.timeout == 60000

    assert mboot.interface.device.timeout == 5000


def test_flash_operation_timeout_restores_on_error() -> None:
    """Test that the original device timeout is restored even when the operation fails."""
    mboot = MagicMock()
    mboot.interface.device.timeout = 5000

    with pytest.raises(SPSDKError):
        with flash_operation_timeout(mboot, ASSUMED_FLASH_THROUGHPUT * 60):
            assert mboot.interface.device.timeout == 60000
            raise SPSDKError("Erase failed")

    assert mboot.interface.device.timeout == 5000


def test_flash_operation_timeout_small_operation() -> None:
    """Test that the timeout is left untouched for a short operation."""
    mboot = MagicMock()
    mboot.interface.device.timeout = 5000

    with flash_operation_timeout(mboot, 1024):
        assert mboot.interface.device.timeout == 5000

    assert mboot.interface.device.timeout == 5000


def test_flash_operation_timeout_unsupported_device() -> None:
    """Test that a device not supporting the timeout reconfiguration is handled gracefully."""
    mboot = MagicMock()
    type(mboot.interface.device).timeout = property(
        lambda self: (_ for _ in ()).throw(NotImplementedError())
    )

    with flash_operation_timeout(mboot, ASSUMED_FLASH_THROUGHPUT * 60):
        pass


@pytest.mark.parametrize(
    "length, alignment, expected",
    [
        # short regions are erased by a single command, there is no progress worth reporting
        (4096, 4096, 4096),
        (MIN_ERASE_PROGRESS_LENGTH, 4096, MIN_ERASE_PROGRESS_LENGTH),
        # longer regions are split into whole erase blocks
        (10 * 4096, 4096, 4096),
        (MAX_ERASE_PROGRESS_STEPS * 4096, 4096, 4096),
        # larger regions use bigger chunks to keep the number of commands bounded
        (2 * MAX_ERASE_PROGRESS_STEPS * 4096, 4096, 2 * 4096),
        # 16 MB with a 64 kB erase block -> 86 chunks of 3 blocks each
        (16 * 1024 * 1024, 64 * 1024, 3 * 64 * 1024),
        # the chunk is always a whole multiple of the erase block
        (150 * 1024, 1024, 2048),
        # degenerate inputs never return a zero chunk
        (0, 4096, 4096),
        (-1, 4096, 4096),
        (4096, 0, 1),
    ],
)
def test_get_erase_chunk_size(length: int, alignment: int, expected: int) -> None:
    """Test the erase chunk size calculation used to report the erase progress."""
    assert get_erase_chunk_size(length, alignment) == expected


@pytest.mark.parametrize(
    "length, alignment",
    [
        (4096, 4096),
        (10 * 4096, 4096),
        (16 * 1024 * 1024, 64 * 1024),
        (150 * 1024, 1024),
    ],
)
def test_get_erase_chunk_size_bounded_command_count(length: int, alignment: int) -> None:
    """Test that the number of erase commands never exceeds the configured limit."""
    chunk = get_erase_chunk_size(length, alignment)
    assert chunk % alignment == 0
    commands = -(-length // chunk)  # ceil division
    assert commands <= MAX_ERASE_PROGRESS_STEPS


@pytest.mark.parametrize("length", [1024, 4096, MIN_ERASE_PROGRESS_LENGTH])
def test_get_erase_chunk_size_short_region_single_command(length: int) -> None:
    """Test that a short region is always erased by a single command."""
    assert get_erase_chunk_size(length, 1024) == length


def _erase_mboot_mock() -> MagicMock:
    """Create a McuBoot mock with a numeric device timeout and a successful erase.

    :return: Configured McuBoot mock usable by the chunked erase tests.
    """
    mboot = MagicMock()
    mboot.interface.device.timeout = 5000
    mboot.flash_erase_region.return_value = True
    return mboot


def test_flash_erase_region_with_progress_single_chunk() -> None:
    """Test that a small region is erased by a single command covering the whole region."""
    mboot = _erase_mboot_mock()
    progress: list[tuple[int, int]] = []

    assert flash_erase_region_with_progress(
        mboot,
        address=0x1000,
        length=0x1000,
        alignment=0x1000,
        progress_callback=lambda step, total: progress.append((step, total)),
    )

    mboot.flash_erase_region.assert_called_once_with(address=0x1000, length=0x1000, mem_id=0)
    assert progress == [(0x1000, 0x1000)]


def test_flash_erase_region_with_progress_multiple_chunks() -> None:
    """Test that a large region is split into several commands reporting the progress."""
    mboot = _erase_mboot_mock()
    alignment = 0x1000
    length = 10 * MIN_ERASE_PROGRESS_LENGTH
    chunk = get_erase_chunk_size(length, alignment)
    progress: list[tuple[int, int]] = []

    assert flash_erase_region_with_progress(
        mboot,
        address=0x8000,
        length=length,
        alignment=alignment,
        mem_id=9,
        progress_callback=lambda step, total: progress.append((step, total)),
    )

    expected_calls = -(-length // chunk)
    assert mboot.flash_erase_region.call_count == expected_calls
    # the erased chunks must cover the whole region exactly once, without any gap or overlap
    erased = [
        (call.kwargs["address"], call.kwargs["length"])
        for call in mboot.flash_erase_region.call_args_list
    ]
    assert erased[0][0] == 0x8000
    assert sum(item[1] for item in erased) == length
    for previous, current in zip(erased, erased[1:]):
        assert current[0] == previous[0] + previous[1]
    # every command targets the requested memory
    assert all(call.kwargs["mem_id"] == 9 for call in mboot.flash_erase_region.call_args_list)
    # the progress is reported after every chunk and ends at 100 %
    assert len(progress) == expected_calls
    assert progress[-1] == (length, length)


def test_flash_erase_region_with_progress_unaligned_tail() -> None:
    """Test that the last chunk is shortened so the erase never exceeds the region."""
    mboot = _erase_mboot_mock()
    alignment = 0x400
    length = 150 * 1024

    assert flash_erase_region_with_progress(mboot, address=0, length=length, alignment=alignment)

    erased = [call.kwargs["length"] for call in mboot.flash_erase_region.call_args_list]
    assert sum(erased) == length
    assert all(item <= get_erase_chunk_size(length, alignment) for item in erased)


def test_flash_erase_region_with_progress_aborts_on_failure() -> None:
    """Test that the erase stops at the first failing command."""
    mboot = _erase_mboot_mock()
    mboot.flash_erase_region.side_effect = [True, False, True]
    alignment = 0x1000
    length = 10 * MIN_ERASE_PROGRESS_LENGTH
    progress: list[tuple[int, int]] = []

    assert not flash_erase_region_with_progress(
        mboot,
        address=0,
        length=length,
        alignment=alignment,
        progress_callback=lambda step, total: progress.append((step, total)),
    )

    assert mboot.flash_erase_region.call_count == 2
    # the progress was reported only for the successfully erased chunk
    assert len(progress) == 1


def test_flash_erase_region_with_progress_without_callback() -> None:
    """Test that the erase works without any progress callback."""
    mboot = _erase_mboot_mock()

    assert flash_erase_region_with_progress(mboot, address=0, length=0x4000, alignment=0x1000)
    # a short region is erased by a single command
    assert mboot.flash_erase_region.call_count == 1


def test_flash_erase_region_with_progress_adjusts_timeout() -> None:
    """Test that the timeout is adjusted per chunk and restored after the erase."""
    mboot = _erase_mboot_mock()
    timeouts: list[int] = []

    def record_timeout(**_kwargs: int) -> bool:
        """Record the timeout active during the erase command.

        :return: Always True to simulate a successful erase.
        """
        timeouts.append(mboot.interface.device.timeout)
        return True

    mboot.flash_erase_region.side_effect = record_timeout
    alignment = ASSUMED_FLASH_THROUGHPUT * 60
    length = 2 * MAX_ERASE_PROGRESS_STEPS * alignment

    assert flash_erase_region_with_progress(mboot, address=0, length=length, alignment=alignment)

    # every chunk is erased with an increased timeout derived from the chunk size
    assert timeouts and all(item > 5000 for item in timeouts)
    assert mboot.interface.device.timeout == 5000
