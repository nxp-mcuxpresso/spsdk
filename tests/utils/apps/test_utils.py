#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.apps import utils


def test_split_string():
    assert ['12', '34', '5'] == utils._split_string('12345', length=2)
    assert ['123', '123'] == utils._split_string('123123', length=3)


def test_format_data():
    data = bytes(range(20))
    expect_8 = "00 01 02 03 04 05 06 07\n08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
    assert expect_8 == utils.format_raw_data(data, use_hexdump=False, line_length=8)
    expect_16 = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n10 11 12 13"
    assert expect_16 == utils.format_raw_data(data, use_hexdump=False, line_length=16)