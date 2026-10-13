#!/usr/bin/env python
#
# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Bootable Image Segments testing module.

This module contains unit tests for bootable image segments functionality,
specifically focusing on the SegmentImageVersionAntiPole class which handles
image version antipole segments in bootable images.
"""

from typing import Any

import pytest

from spsdk.exceptions import SPSDKParsingError, SPSDKValueError
from spsdk.image.bootable_image.segments import (
    Segment,
    SegmentImageVersion,
    SegmentImageVersionAntiPole,
)
from spsdk.image.exceptions import SPSDKSegmentNotPresent
from spsdk.image.mem_type import MemoryType
from spsdk.utils.binary_image import BinaryImage
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision

FAMILY = FamilyRevision("lpc55s3x")
MEM = MemoryType.FLEXSPI_NOR


def _base_segment(offset: int = 0) -> Segment:
    """Build a bare base Segment instance."""
    return Segment(offset, family=FAMILY, mem_type=MEM)


def _bin(data: bytes, size: int = 4) -> BinaryImage:
    """Build a simple BinaryImage."""
    return BinaryImage(name="x", size=size, binary=data)


@pytest.mark.parametrize(
    "config,binary",
    [
        ({}, "ffffffff"),  # unprogrammed
        ({"image_version": 65535}, "ffff0000"),  # max value
        ({"image_version": 12345}, "3930c6cf"),  # valid version
        ({"image_version": 98765}, "cd81327e"),  # more than 4 bytes
    ],
)
def test_segment_image_version_antipole_load_from_config(
    config: dict[str, Any], binary: str
) -> None:
    """Test segment image version antipole configuration loading.

    This test verifies that a SegmentImageVersionAntiPole can be properly loaded
    from a configuration dictionary and produces the expected binary output.

    :param config: Configuration dictionary containing image version antipole settings.
    :param binary: Expected hexadecimal string representation of the exported segment.
    """
    segment = SegmentImageVersionAntiPole(
        0, family=FamilyRevision("lpc55s3x"), mem_type=MemoryType.FLEXSPI_NOR
    )
    segment.load_config(Config(config))
    assert segment.cfg_key() == "image_version"
    assert segment.export().hex() == binary


@pytest.mark.parametrize(
    "binary,config",
    [
        ("ffffffff", 65535),  # unprogrammed
        ("ffff0000", 65535),  # max value
        ("3930c6cf", 12345),  # valid version
        ("cd81327e", 33229),  # more than 4 bytes
    ],
)
def test_segment_image_version_antipole_parse(binary: str, config: int) -> None:
    """Test segment image version antipole parsing functionality.

    This test verifies that a SegmentImageVersionAntiPole can correctly parse
    binary data and generate the expected configuration value.

    :param binary: Hexadecimal string representation of binary data to parse
    :param config: Expected configuration integer value after parsing
    :raises AssertionError: When parsed configuration doesn't match expected value
    """
    segment = SegmentImageVersionAntiPole(
        0, family=FamilyRevision("lpc55s3x"), mem_type=MemoryType.FLEXSPI_NOR
    )
    segment.parse_binary(bytes.fromhex(binary))
    assert segment.create_config("") == config


# Base Segment class


def test_segment_size_default() -> None:
    """Base Segment.size returns -1."""
    assert _base_segment().size == -1


def test_segment_export_and_len_empty() -> None:
    """Empty segment exports empty bytes and has zero length."""
    seg = _base_segment()
    assert seg.export() == b""
    assert len(seg) == 0


def test_segment_repr_equals_str() -> None:
    """Segment __repr__ and __str__ describe the segment."""
    seg = _base_segment()
    assert "Bootable image segment" in repr(seg)
    assert repr(seg) == str(seg)


def test_segment_is_present_false_when_empty() -> None:
    """is_present is False when the segment has no content."""
    assert _base_segment().is_present is False


def test_segment_clear_resets_raw_block() -> None:
    """clear() resets raw_block back to None."""
    seg = _base_segment()
    seg.raw_block = _bin(b"\x00\x00\x00\x00")
    seg.clear()
    assert seg.raw_block is None


def test_segment_full_image_offset_none_raises() -> None:
    """full_image_offset raises when the offset is undefined."""
    seg = _base_segment()
    seg._offset = None  # type: ignore[assignment]
    with pytest.raises(SPSDKValueError):
        _ = seg.full_image_offset


def test_segment_full_image_offset_negative() -> None:
    """full_image_offset returns the raw negative offset unchanged."""
    assert _base_segment(-5).full_image_offset == -5


def test_segment_info_not_present() -> None:
    """info() reports 'Not present' for an empty segment."""
    assert "Not present" in _base_segment().info(0)


def test_segment_info_with_actual_offset() -> None:
    """info() prints the provided actual offset."""
    seg = _base_segment(0)
    seg.raw_block = _bin(b"\x01\x01\x01\x01")
    assert "0x00000100" in seg.info(0, actual_offset=0x100)


def test_segment_info_positive_offset() -> None:
    """info() prints the segment's own positive offset."""
    seg = _base_segment(0x40)
    seg.raw_block = _bin(b"\x01\x01\x01\x01")
    assert "0x00000040" in seg.info(0)


def test_segment_info_auto_offset() -> None:
    """info() prints 'Auto' for a negative offset."""
    seg = _base_segment(-1)
    seg.raw_block = _bin(b"\x01\x01\x01\x01")
    assert "Auto" in seg.info(0)


def test_segment_image_info_offset() -> None:
    """image_info() wraps content preserving the offset."""
    seg = _base_segment(0x10)
    seg.raw_block = _bin(b"\x02\x02\x02\x02")
    assert seg.image_info().offset == 0x10


def test_segment_parse_not_implemented() -> None:
    """Base Segment.parse raises NotImplementedError."""
    with pytest.raises(NotImplementedError):
        Segment.parse(b"")


def test_segment_find_segment_offset_zero() -> None:
    """find_segment_offset returns 0 for the base segment."""
    assert Segment.find_segment_offset(b"1234") == 0


def test_segment_base_parse_binary_too_small() -> None:
    """Base parse_binary raises when the binary is smaller than the segment size."""
    seg = SegmentImageVersion(0, family=FAMILY, mem_type=MEM)
    with pytest.raises(SPSDKParsingError):
        Segment.parse_binary(seg, b"\x00")


def test_segment_base_parse_binary_padding() -> None:
    """Base parse_binary raises SPSDKSegmentNotPresent for padding-only content."""
    seg = SegmentImageVersion(0, family=FAMILY, mem_type=MEM)
    with pytest.raises(SPSDKSegmentNotPresent):
        Segment.parse_binary(seg, b"\x00\x00\x00\x00")


def test_segment_base_parse_binary_ok() -> None:
    """Base parse_binary stores raw block for non-padding content."""
    seg = SegmentImageVersion(0, family=FAMILY, mem_type=MEM)
    Segment.parse_binary(seg, b"\x12\x34\x56\x78")
    assert seg.raw_block is not None
    assert seg.not_parsed is False


# SegmentImageVersion


def test_image_version_create_config_not_present() -> None:
    """create_config returns 0 when the segment is not present."""
    seg = SegmentImageVersion(0, family=FAMILY, mem_type=MEM)
    assert seg.create_config("") == 0


def test_image_version_load_config_invalid() -> None:
    """load_config raises for a non-integer version value."""
    seg = SegmentImageVersion(0, family=FAMILY, mem_type=MEM)
    with pytest.raises(SPSDKValueError):
        seg.load_config(Config({"image_version": "not-int"}))


def test_image_version_verify_with_value() -> None:
    """verify() records the image version without errors for valid data."""
    seg = SegmentImageVersion(0, family=FAMILY, mem_type=MEM)
    seg.load_config(Config({"image_version": 12345}))
    assert not seg.verify().has_errors


# SegmentImageVersionAntiPole


def test_antipole_create_config_not_present() -> None:
    """create_config returns 0 when the antipole segment is not present."""
    seg = SegmentImageVersionAntiPole(0, family=FAMILY, mem_type=MEM)
    assert seg.create_config("") == 0


def test_antipole_load_config_invalid() -> None:
    """load_config raises for a non-integer version value."""
    seg = SegmentImageVersionAntiPole(0, family=FAMILY, mem_type=MEM)
    with pytest.raises(SPSDKValueError):
        seg.load_config(Config({"image_version": "not-int"}))


def test_antipole_parse_binary_too_small() -> None:
    """parse_binary raises when the binary is smaller than the segment size."""
    seg = SegmentImageVersionAntiPole(0, family=FAMILY, mem_type=MEM)
    with pytest.raises(SPSDKParsingError):
        seg.parse_binary(b"\x00")


def test_antipole_verify_valid() -> None:
    """verify() succeeds for a matching version/antipole pair."""
    seg = SegmentImageVersionAntiPole(0, family=FAMILY, mem_type=MEM)
    seg.load_config(Config({"image_version": 12345}))
    assert not seg.verify().has_errors


def test_antipole_verify_unprogrammed_warns() -> None:
    """verify() warns for the unprogrammed default value."""
    seg = SegmentImageVersionAntiPole(0, family=FAMILY, mem_type=MEM)
    seg.load_config(Config({}))
    v = seg.verify()
    assert not v.has_errors


def test_antipole_verify_mismatch_error() -> None:
    """verify() reports an error when version and antipole do not match."""
    seg = SegmentImageVersionAntiPole(0, family=FAMILY, mem_type=MEM)
    seg.parse_binary(b"\x00\x00\x00\x00")
    assert seg.verify().has_errors
