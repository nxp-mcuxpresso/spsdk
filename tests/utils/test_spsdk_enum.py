#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import pytest

from spsdk.exceptions import SPSDKKeyError
from spsdk.utils.spsdk_enum import SpsdkEnum


class SpsdkEnumNumbers(SpsdkEnum):
    ONE = (1, "TheOne")
    TWO = (2, "TheTwo", "Just two.")
    THREE = (3, "TheThree")
    FOUR = (4, "TheFour", "Just four.")


class SpsdkEnumDays(SpsdkEnum):
    MONDAY = (1, "Monday")
    TUESDAY = (1, "Tuesday")


def test_simple_check() -> None:
    assert SpsdkEnumNumbers.ONE.tag == 1
    assert SpsdkEnumNumbers.TWO.tag == 2
    assert SpsdkEnumNumbers.THREE.tag == 3
    assert SpsdkEnumNumbers.FOUR.tag == 4


def test_equals() -> None:
    assert SpsdkEnumNumbers.ONE == 1
    assert SpsdkEnumNumbers.TWO == 2
    assert SpsdkEnumNumbers.ONE != 2


def test_from_tag() -> None:
    two = SpsdkEnumNumbers.from_tag(2)
    assert two.tag == 2
    assert two.label == "TheTwo"
    assert two.description == "Just two."
    two = SpsdkEnumNumbers.from_tag(SpsdkEnumNumbers.TWO)
    assert two.tag == 2
    assert two.label == "TheTwo"
    assert two.description == "Just two."
    with pytest.raises(SPSDKKeyError):
        SpsdkEnumNumbers.from_tag(10)


def test_from_name() -> None:
    two = SpsdkEnumNumbers.from_label("TheTwo")
    assert two.tag == 2
    assert two.label == "TheTwo"
    assert two.description == "Just two."
    with pytest.raises(SPSDKKeyError):
        SpsdkEnumNumbers.from_label("TEN")


def test_get_desc() -> None:
    assert SpsdkEnumNumbers.get_description(2) == "Just two."
    assert SpsdkEnumNumbers.get_description(SpsdkEnumNumbers.TWO) == "Just two."
    assert SpsdkEnumNumbers.get_description(1) == None
    assert SpsdkEnumNumbers.get_description(SpsdkEnumNumbers.ONE) == None
    assert SpsdkEnumNumbers.get_description(SpsdkEnumNumbers.ONE, "Default") == "Default"
    assert SpsdkEnumNumbers.get_description(1, "Default") == "Default"
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description(10)
    # Backwards incompatible!!
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description(10, "default")
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description("ONE")
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description("TheTwo")


def test_get_identifier() -> None:
    assert SpsdkEnumNumbers.get_label(1) == "TheOne"
    assert SpsdkEnumNumbers.get_label(SpsdkEnumNumbers.ONE) == "TheOne"
    assert SpsdkEnumNumbers.get_label(2) == "TheTwo"
    assert SpsdkEnumNumbers.get_label(SpsdkEnumNumbers.TWO) == "TheTwo"
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_label(10)


def test_contains() -> None:
    assert SpsdkEnumNumbers.ONE in SpsdkEnumNumbers
    assert not (SpsdkEnumNumbers.ONE not in SpsdkEnumNumbers)
    assert SpsdkEnumNumbers.TWO in SpsdkEnumNumbers
    assert SpsdkEnumNumbers.ONE in [SpsdkEnumNumbers.ONE]
    assert 1 in [SpsdkEnumNumbers.ONE]
    assert 1 in [5, SpsdkEnumNumbers.ONE]
    assert 2 not in [5, SpsdkEnumNumbers.ONE]
    assert 2 in [SpsdkEnumNumbers.ONE, SpsdkEnumNumbers.TWO]


def test_enum_len():
    assert len(SpsdkEnumNumbers) == 4


def test_enum_get_item():
    value = SpsdkEnumNumbers["ONE"]
    assert value.label == "TheOne"
    with pytest.raises(KeyError):
        SpsdkEnumNumbers["TEN"]


def test_enum_contains():
    assert SpsdkEnumNumbers.contains("TheOne")
    assert SpsdkEnumNumbers.contains(1)
    assert SpsdkEnumNumbers.contains("TheTwo")
    assert SpsdkEnumNumbers.contains(2)
    assert not SpsdkEnumNumbers.contains("Whatever")
    assert not SpsdkEnumNumbers.contains(10)


def test_enum_isinstance():
    assert isinstance(SpsdkEnumNumbers.ONE, SpsdkEnumNumbers)
    assert isinstance(SpsdkEnumNumbers.TWO, SpsdkEnumNumbers)
    assert not isinstance(SpsdkEnumNumbers.ONE, SpsdkEnumDays)
    assert not isinstance(1, SpsdkEnumDays)
