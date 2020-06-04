#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


class A:
    def __eq__(self, other):
        return isinstance(other, self.__class__) and vars(other) == vars(self)


class B(A):
    pass


def test_blank():
    a1, a2 = A(), A()
    assert a1 == a2

    a, b = A(), B()
    assert a != b


def test_extra_array():
    a1, a2 = A(), A()
    assert a1 == a2

    a1.data = []
    assert a1 != a2

    a2.data = []
    assert a1 == a2

    for i in range(10):
        a1.data.append(i)
    assert a1 != a2

    for i in range(9):
        a2.data.append(i)
    assert a1 != a2

    a2.data.append(9)
    assert a1 == a2
