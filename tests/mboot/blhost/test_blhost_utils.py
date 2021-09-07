#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Testing utilities for the BLHost application."""
import os
from typing import List, Tuple

import pytest

from spsdk import SPSDKError
from spsdk.apps.blhost_helper import (
    SegmentInfo,
    parse_image_file,
    parse_key_prov_key_type,
    parse_property_tag,
    parse_trust_prov_key_type,
    parse_trust_prov_oem_key_type,
    parse_trust_prov_wrapping_key_type,
)


@pytest.mark.parametrize(
    "input,expected",
    [
        ("1", 1),
        ("0xa", 10),
        ("0b100", 4),
        ("list-properties", 0),
        ("target-version", 24),
        ("abc", 0xFF),
        ("012", 0xFF),
        ("some-nonsense", 0xFF),
    ],
)
def test_parse_property_tag(input, expected):
    actual = parse_property_tag(input)
    assert actual == expected


@pytest.mark.parametrize(
    "input, expected",
    [
        ("1", 1),
        ("0xa", 10),
        ("0b100", 4),
        ("abc", 0xFF),
        ("012", 0xFF),
        ("some-nonsense", 0xFF),
        ("sbkek", 3),
        ("UDS", 12),
    ],
)
def test_parse_key_prov_key_type(input, expected):
    actual = parse_key_prov_key_type(input)
    assert actual == expected


@pytest.mark.parametrize(
    "path, error_msg",
    [
        ("evkmimxrt595_gpio_led_output.axf", "Elf file is not supported"),
        ("iled_blinky_ide_1060.elf", "Elf file is not supported"),
        ("iled_blinky.out", "file is not supported"),
        ("iled_blinky_ide_1060_60002000.bin", "use write-memory command"),
    ],
)
def test_parse_image_file_invalid(path, error_msg, data_dir):
    with pytest.raises(SPSDKError, match=error_msg):
        parse_image_file(os.path.join(data_dir, path))


@pytest.mark.parametrize(
    "path, segment_info_list",
    [
        (
            "evkmimxrt685_led_blinky_ext_flash.srec",
            [SegmentInfo(start=0x08001000, length=0x54EC, data_bin=None)],
        ),
        (
            "sdk20-app.bin.s19",
            [
                SegmentInfo(start=0x7F400, length=512, data_bin=None),
                SegmentInfo(start=0x80000, length=360, data_bin=None),
                SegmentInfo(start=0x80180, length=58146, data_bin=None),
            ],
        ),
        (
            "iled_blinky_ide_1060.hex",
            [SegmentInfo(start=0x60002000, length=0x32CC, data_bin=None)],
        ),
    ],
)
def test_parse_image_file(path, segment_info_list: List[SegmentInfo], data_dir):
    result = parse_image_file(os.path.join(data_dir, path))
    assert len(result) == len(segment_info_list)
    for current, ref in zip(result, segment_info_list):
        assert current.start == ref.start
        assert current.length == ref.length
        assert len(current.data_bin) == current.length


@pytest.mark.parametrize(
    "path, segment_info_list",
    [
        (
            "evkmimxrt685_led_blinky_ext_flash.srec",
            [SegmentInfo(start=0x08001000, length=0x54EC, data_bin=None)],
        ),
        (
            "sdk20-app.s19",
            [
                SegmentInfo(start=0x7F400, length=512, data_bin=None),
                SegmentInfo(start=0x80000, length=360, data_bin=None),
                SegmentInfo(start=0x80180, length=58146, data_bin=None),
            ],
        ),
        (
            "iled_blinky_ide_1060.hex",
            [SegmentInfo(start=0x60002000, length=0x32CC, data_bin=None)],
        ),
    ],
)
def test_parse_image_file(path, segment_info_list: List[SegmentInfo], data_dir):
    result = parse_image_file(os.path.join(data_dir, path))
    assert len(result) == len(segment_info_list)
    for current, ref in zip(result, segment_info_list):
        assert current.start == ref.start
        assert current.length == ref.length
        assert len(current.data_bin) == current.length


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
def test_parse_image_file_aligned_sizes(path, aligned_sizes: List[Tuple[int, int]], data_dir):
    result = parse_image_file(os.path.join(data_dir, path))
    assert len(result) == len(aligned_sizes)
    for segment, expected in zip(result, aligned_sizes):
        assert segment.aligned_start == expected[0]
        assert segment.aligned_length == expected[1]


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
    ],
)
def test_parse_tp_prov_oem_key_type(input_value, expected_output):
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
def test_parse_tp_prov_key_type(input_value, expected_output):
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
def test_parse_tp_prov_wrapping_key_type(input_value, expected_output):
    actual = parse_trust_prov_wrapping_key_type(input_value)
    assert actual == expected_output
