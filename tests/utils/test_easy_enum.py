#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2021 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

from spsdk.exceptions import SPSDKError
import pytest

from spsdk.utils.easy_enum import Enum


class TestEnum(Enum):
    ONE = 1
    TWO = (2, "TheTwo", "Just two.")


class TestEnum2(TestEnum):
    THREE = 3
    FOUR = (4, "TheFour", "Just four.")


def test_simple() -> None:
    assert TestEnum.ONE == 1
    assert TestEnum.TWO == 2
    assert TestEnum2.ONE == 1
    assert TestEnum2.TWO == 2
    assert TestEnum2.THREE == 3
    assert TestEnum2.FOUR == 4


def test_get() -> None:
    # value -> name
    assert TestEnum.get(1) == "ONE"
    assert TestEnum[2] == "TheTwo"
    assert TestEnum.get(TestEnum.ONE) == "ONE"
    assert TestEnum[TestEnum.TWO] == "TheTwo"
    # non-existing value
    assert TestEnum.get(3) is None
    assert TestEnum.get(3, 3) == 3
    with pytest.raises(KeyError):
        TestEnum[3]
    # name -> value
    assert TestEnum.get("ONE") == 1
    assert TestEnum.get("TheTwo") == 2
    assert TestEnum.get("THREE") is None
    assert TestEnum.get("three", 3) == 3
    with pytest.raises(KeyError):
        TestEnum["THREE"]
    # case insensitive
    assert TestEnum.get("one") == 1
    assert TestEnum["thetwo"] == 2
    with pytest.raises(KeyError):
        TestEnum["three"]

    # value -> name
    assert TestEnum2.get(1) == "ONE"
    assert TestEnum2[2] == "TheTwo"
    assert TestEnum2.get(TestEnum.ONE) == "ONE"
    assert TestEnum2[TestEnum.TWO] == "TheTwo"
    assert TestEnum2.get(3) == "THREE"
    assert TestEnum2[4] == "TheFour"
    assert TestEnum2.get(TestEnum2.THREE) == "THREE"
    assert TestEnum2[TestEnum2.FOUR] == "TheFour"
    # non-existing value
    assert TestEnum2.get(5) is None
    assert TestEnum.get(5, 5) == 5
    with pytest.raises(KeyError):
        TestEnum[5]
    # name -> value
    assert TestEnum2.get("ONE") == 1
    assert TestEnum2.get("TheTwo") == 2
    assert TestEnum2.get("three", 3) == 3
    assert TestEnum2.get("FIVE") is None
    with pytest.raises(KeyError):
        TestEnum["FIVE"]
    # case insensitive
    assert TestEnum2.get("one") == 1
    assert TestEnum2["thetwo"] == 2
    assert TestEnum2["three"] == 3
    assert TestEnum2["thefour"] == 4
    with pytest.raises(KeyError):
        TestEnum2["five"]


def test_desc() -> None:
    # desc for value
    assert TestEnum.desc(1) == ""
    assert TestEnum.desc(TestEnum.TWO) == "Just two."
    # desc for name
    assert TestEnum.desc("ONE") == ""
    assert TestEnum.desc("thetwo") == "Just two."
    # default
    assert TestEnum.desc("ONE", "default") == ""
    assert TestEnum.desc("thetwo", "default") == "Just two."
    # invalid key
    assert TestEnum.desc("three") == ""
    assert TestEnum.desc("three", "default") == "default"
    # desc for value
    assert TestEnum2.desc(1) == ""
    assert TestEnum2.desc(TestEnum2.TWO) == "Just two."
    assert TestEnum2.desc(3) == ""
    assert TestEnum2.desc(TestEnum2.FOUR) == "Just four."
    # desc for name
    assert TestEnum2.desc("ONE") == ""
    assert TestEnum2.desc("thetwo") == "Just two."
    assert TestEnum2.desc("THREE") == ""
    assert TestEnum2.desc("thefour") == "Just four."
    # default
    assert TestEnum2.desc("ONE", "default") == ""
    assert TestEnum2.desc("thetwo", "default") == "Just two."
    assert TestEnum2.desc("THREE", "default") == ""
    assert TestEnum2.desc("thefour", "default") == "Just four."
    # invalid key
    assert TestEnum2.desc("five") == ""
    assert TestEnum2.desc("five", "default") == "default"


def test_name() -> None:
    assert TestEnum.name(1) == "ONE"
    assert TestEnum.name(2) == "TheTwo"
    assert TestEnum.name(TestEnum.ONE) == "ONE"
    assert TestEnum.name(TestEnum.TWO) == "TheTwo"
    # default
    assert TestEnum.name(1, "?") == "ONE"
    assert TestEnum.name(TestEnum.TWO, "?") == "TheTwo"
    assert TestEnum.name(3, "three") == "three"
    with pytest.raises(KeyError):
        TestEnum[3]
    # test TestEnum2
    assert TestEnum2.name(1) == "ONE"
    assert TestEnum2.name(2) == "TheTwo"
    assert TestEnum2.name(TestEnum2.ONE) == "ONE"
    assert TestEnum2.name(TestEnum2.TWO) == "TheTwo"
    assert TestEnum2.name(3) == "THREE"
    assert TestEnum2.name(4) == "TheFour"
    assert TestEnum2.name(TestEnum2.ONE) == "ONE"
    assert TestEnum2.name(TestEnum2.TWO) == "TheTwo"
    assert TestEnum2.name(TestEnum2.THREE) == "THREE"
    assert TestEnum2.name(TestEnum2.FOUR) == "TheFour"
    # default
    assert TestEnum2.name(1, "?") == "ONE"
    assert TestEnum2.name(TestEnum2.TWO, "?") == "TheTwo"
    assert TestEnum2.name(3, "?") == "THREE"
    assert TestEnum2.name(4, "?") == "TheFour"
    assert TestEnum2.name(5, "five") == "five"
    assert TestEnum2.name(TestEnum2.FOUR, "?") == "TheFour"
    with pytest.raises(KeyError):
        TestEnum2[5]


def test_tags() -> None:
    tags = TestEnum.tags()
    assert tags is not None
    assert len(tags) == 2
    assert tags[0] == 1
    assert tags[1] == 2
    # test iter even it is deprecated
    for index, val in enumerate(TestEnum):
        assert index + 1 == val[1]
        assert val[0] == TestEnum.name(val[1])
        assert val[2] == TestEnum.desc(val[1])

    tags = TestEnum2.tags()
    assert tags is not None
    assert len(tags) == 4
    assert tags[0] == 1
    assert tags[1] == 2
    assert tags[2] == 3
    assert tags[3] == 4
    # test iter even it is deprecated
    for index, val in enumerate(TestEnum2):
        assert index + 1 == val[1]
        assert val[0] == TestEnum2.name(val[1])
        assert val[2] == TestEnum2.desc(val[1])


def test_from_int() -> None:
    assert TestEnum.from_int(1) == TestEnum.ONE
    assert TestEnum.from_int(2) == TestEnum.TWO
    with pytest.raises(SPSDKError):
        TestEnum.from_int(3)
    with pytest.raises(SPSDKError):
        TestEnum.from_int(0)

    assert TestEnum2.from_int(1) == TestEnum2.ONE
    assert TestEnum2.from_int(2) == TestEnum2.TWO
    assert TestEnum2.from_int(3) == TestEnum2.THREE
    assert TestEnum2.from_int(4) == TestEnum2.FOUR
    with pytest.raises(SPSDKError):
        TestEnum.from_int(5)


def test_contains() -> None:
    # value
    assert 1 in TestEnum
    assert 2 in TestEnum
    # enum
    assert TestEnum.ONE in TestEnum
    assert TestEnum.TWO in TestEnum
    # name
    assert "ONE" in TestEnum
    assert "TheTwo" in TestEnum
    # case sensitive
    assert "one" not in TestEnum
    # not contains
    assert "three" not in TestEnum
    assert 3 not in TestEnum

    # value
    assert 1 in TestEnum2
    assert 2 in TestEnum2
    assert 3 in TestEnum2
    assert 4 in TestEnum2
    # enum
    assert TestEnum2.ONE in TestEnum2
    assert TestEnum2.TWO in TestEnum2
    assert TestEnum2.THREE in TestEnum2
    assert TestEnum2.FOUR in TestEnum2
    # name
    assert "ONE" in TestEnum2
    assert "TheTwo" in TestEnum2
    assert "THREE" in TestEnum2
    assert "TheFour" in TestEnum2
    # case sensitive
    assert "one" not in TestEnum2
    assert "three" not in TestEnum2
    # not contains
    assert "five" not in TestEnum2
    assert 5 not in TestEnum2
