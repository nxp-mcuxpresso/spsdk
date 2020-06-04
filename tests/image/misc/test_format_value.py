#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest
from spsdk.image.misc import format_value


@pytest.mark.parametrize(
    "value,size,expected",
    [
        (0, 2, "0b00"), (0, 4, "0b0000"), (0, 10, "0b00_0000_0000"),
        (0, 8, "0x00"), (0, 16, "0x0000"),
        (0, 32, "0x0000_0000"),
        (0, 64, "0x0000_0000_0000_0000")
    ]
)
def test_format_value(value, size, expected):
    assert format_value(value, size) == expected
