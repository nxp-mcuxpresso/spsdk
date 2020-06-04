#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from spsdk.image.misc import parse_int


@pytest.mark.parametrize(
    "test_input,expected",
    [
        ("0", 0), ("0x0", 0), ("0u", 0), ("0x0u", 0), ("1", 1), ("1ull", 1), ("2LU", 2),
        ("1l", 1), ("10", 10), ("0x10", 16), ("0x20u", 32), ("0xff", 255), ("0xFFFFu", 65535),
        ("0b1_0_0_0", 8), ("0x00_10", 16), ("5", 5), ("4_5", 45)
    ],
)
def test_parse_int(test_input, expected):
    assert parse_int(test_input) == expected


@pytest.mark.parametrize(
    "test_input", ['', 'x', '.0', '1whatever*', ' 3 ']
)
def test_parse_int_invalid_input(test_input):
    """ Test invalid inputs for parse_int() """
    with pytest.raises(ValueError):
        parse_int(test_input)

