#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.image.hab_audit_log import parse_hab_log, get_hab_enum_descr
from spsdk.utils.easy_enum import Enum


class TestEnum(Enum):
    TEST = (0xA5, 'Test descr')


def test_get_hab_enum_descr():
    """Test `get_hab_enum_descr`"""
    # test known value
    t = get_hab_enum_descr(TestEnum, 0xA5)
    assert t == 'Test descr  (0xa5)'

    # test unknown value
    t = get_hab_enum_descr(TestEnum, 0xFF)
    assert t == '0xff = Unknown value'


def test_parse_hab_log():
    """Test `parse_hab_log` function. """
    lines = parse_hab_log(0xF0, 0xCC, 0xAA, b'')
    assert lines
    lines = parse_hab_log(51, 240, 102, b'\xdb\x00\x08\x43\x33\x22\x0a\x00')
    assert lines
    lines = parse_hab_log(51, 240, 102, b'\xdb\x00\x08\x43\x33\x22\x0a\x00' + b'\x00' * 60)
    assert lines
