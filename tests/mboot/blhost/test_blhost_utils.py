#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Testing utilities for the BLHost application."""
import pytest

from spsdk.apps.blhost_helper import parse_key_prov_key_type, parse_property_tag


@pytest.mark.parametrize(
    'input,expected',
    [
        ('1', 1), ('0xa', 10), ('0b100', 4),
        ('list-properties', 0), ('target-version', 24),
        ('abc', 0xFF), ('012', 0xFF), ('some-nonsense', 0xFF)
    ]
)
def test_parse_property_tag(input, expected):
    actual = parse_property_tag(input)
    assert actual == expected


@pytest.mark.parametrize(
    'input, expected',
    [
        ('1', 1), ('0xa', 10), ('0b100', 4),
        ('abc', 0xFF), ('012', 0xFF), ('some-nonsense', 0xFF),
        ('sbkek', 3), ('UDS', 12)
    ]
)
def test_parse_key_prov_key_type(input, expected):
    actual = parse_key_prov_key_type(input)
    assert actual == expected
