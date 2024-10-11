#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Testing utilities for the BLHost application."""
import os

import pytest

from spsdk.apps.blhost_helper import (
    parse_key_prov_key_type,
    parse_property_tag,
    parse_trust_prov_key_type,
    parse_trust_prov_oem_key_type,
    parse_trust_prov_wrapping_key_type,
)
from spsdk.utils.images import BinaryImage
from spsdk.utils.interfaces.device.usbsio_device import UsbSioDevice


@pytest.mark.parametrize(
    "input,expected",
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
def test_parse_property_tag(input, expected):
    actual = parse_property_tag(input)
    assert actual == expected


@pytest.mark.parametrize(
    "input,family,expected",
    [
        ("verify-erase", "kw45b41z8", 10),
        ("verify-erase", "k32w148", 10),
        ("verify-erase", None, 0xFF),
        ("current-version", None, 1),
        ("current-version", "kw45b41z8", 1),
        ("current-version", "k32w148", 1),
    ],
)
def test_parse_property_tag_override(input, family, expected):
    actual = parse_property_tag(input, family)
    assert actual == expected


@pytest.mark.parametrize(
    "input, expected",
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
def test_parse_key_prov_key_type(input, expected):
    actual = parse_key_prov_key_type(input)
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
def test_parse_image_file(path, segment_info_list: list[tuple[int, int]], data_dir):
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
def test_parse_image_file_aligned_sizes(path, aligned_sizes: list[tuple[int, int]], data_dir):
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
