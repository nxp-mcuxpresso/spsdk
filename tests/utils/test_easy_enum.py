#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

import pytest

from spsdk.utils.easy_enum import Enum


class TestEnum(Enum):
    ONE = 1
    TWO = (2, 'TheTwo', 'Just two.')


def test_simple() -> None:
    assert TestEnum.ONE == 1
    assert TestEnum.TWO == 2


def test_get() -> None:
    # value -> name
    assert TestEnum.get(1) == 'ONE'
    assert TestEnum[2] == 'TheTwo'
    assert TestEnum.get(TestEnum.ONE) == 'ONE'
    assert TestEnum[TestEnum.TWO] == 'TheTwo'
    # non-existing value
    assert TestEnum.get(3) is None
    assert TestEnum.get(3, 3) == 3
    with pytest.raises(KeyError):
        TestEnum[3]
    # name -> value
    assert TestEnum.get('ONE') == 1
    assert TestEnum.get('TheTwo') == 2
    assert TestEnum.get('THREE') is None
    assert TestEnum.get('three', 3) == 3
    with pytest.raises(KeyError):
        TestEnum['THREE']
    # case insensitive
    assert TestEnum.get('one') == 1
    assert TestEnum['thetwo'] == 2
    with pytest.raises(KeyError):
        TestEnum['three']


def test_desc() -> None:
    # desc for value
    assert TestEnum.desc(1) == ''
    assert TestEnum.desc(TestEnum.TWO) == 'Just two.'
    # desc for name
    assert TestEnum.desc('ONE') == ''
    assert TestEnum.desc('thetwo') == 'Just two.'
    # default
    assert TestEnum.desc('ONE', 'default') == ''
    assert TestEnum.desc('thetwo', 'default') == 'Just two.'
    # invalid key
    assert TestEnum.desc('three') == ''
    assert TestEnum.desc('three', 'default') == 'default'


def test_name() -> None:
    assert TestEnum.name(1) == 'ONE'
    assert TestEnum.name(2) == 'TheTwo'
    assert TestEnum.name(TestEnum.ONE) == 'ONE'
    assert TestEnum.name(TestEnum.TWO) == 'TheTwo'
    # default
    assert TestEnum.name(1, '?') == 'ONE'
    assert TestEnum.name(TestEnum.TWO, '?') == 'TheTwo'
    assert TestEnum.name(3, 'three') == 'three'
    with pytest.raises(KeyError):
        TestEnum[3]


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


def test_from_int() -> None:
    assert TestEnum.from_int(1) == TestEnum.ONE
    assert TestEnum.from_int(2) == TestEnum.TWO
    with pytest.raises(ValueError):
        TestEnum.from_int(3)
    with pytest.raises(ValueError):
        TestEnum.from_int(0)


def test_contains() -> None:
    # value
    assert 1 in TestEnum
    assert 2 in TestEnum
    # enum
    assert TestEnum.ONE in TestEnum
    assert TestEnum.TWO in TestEnum
    # name
    assert 'ONE' in TestEnum
    assert 'TheTwo' in TestEnum
    # case sensitive
    assert 'one' not in TestEnum
    # not contains
    assert 'three' not in TestEnum
    assert 3 not in TestEnum
