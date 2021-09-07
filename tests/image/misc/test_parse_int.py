#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.exceptions import SPSDKError
import pytest

from spsdk.image.misc import parse_int, size_fmt


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("0", 0),
        ("0x0", 0),
        ("0u", 0),
        ("0x0u", 0),
        ("1", 1),
        ("1ull", 1),
        ("2LU", 2),
        ("1l", 1),
        ("10", 10),
        ("0x10", 16),
        ("0x20u", 32),
        ("0xff", 255),
        ("0xFFFFu", 65535),
        ("0b1_0_0_0", 8),
        ("0x00_10", 16),
        ("5", 5),
        ("4_5", 45),
    ],
)
def test_parse_int(test_input, expected):
    assert parse_int(test_input) == expected


@pytest.mark.parametrize("test_input", ["", "x", ".0", "1whatever*", " 3 "])
def test_parse_int_invalid_input(test_input):
    """ Test invalid inputs for parse_int() """
    with pytest.raises(SPSDKError):
        parse_int(test_input)


@pytest.mark.parametrize(
    "input_value, use_kibibyte, expected",
    [
        (0, False, "0.0 B"),
        (0, True, "0.0 B"),
        (1568, True, "1.5 kiB"),
        (1568, False, "1.6 kB"),
        (177768, True, "173.6 kiB"),
        (157768, False, "157.8 kB"),
        (15565654654654654654668, False, "15565.7 PB"),
        (15565654654654654654668, True, "13501.1 PiB"),
    ],
)
def test_size_format(input_value, use_kibibyte, expected):
    assert size_fmt(input_value, use_kibibyte) == expected
