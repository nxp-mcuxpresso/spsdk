#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Test module for SPSDK equality comparison utilities.

This module contains unit tests for validating object equality operations
and comparison functionality within the SPSDK framework. It provides test
classes and comprehensive test cases to ensure proper behavior of equality
checks across different object types and states.
"""


class A:
    """SPSDK test utility class for equality comparison.

    This class provides a base implementation for object equality testing
    by comparing class types and instance variables, commonly used in
    SPSDK unit tests for validating object state and behavior.
    """

    def __eq__(self, other: object) -> bool:
        """Check equality between two objects.

        Compare this instance with another object by checking if they are of the same class
        and have identical instance variables.

        :param other: Object to compare with this instance.
        :return: True if objects are equal (same class and identical vars), False otherwise.
        """
        return isinstance(other, self.__class__) and vars(other) == vars(self)


class B(A):
    """Looking at this class, it's a simple inheritance from class A with no additional implementation.

    Since this appears to be in a test file (`tests/utils/test_eq.py`), this is likely a test helper class
    used for equality testing scenarios.

    Test helper class extending class A for equality testing.
    This class inherits all functionality from class A without modifications,
    typically used in unit tests to verify equality operations and inheritance
    behavior.
    """


def test_blank() -> None:
    """Test equality comparison between same and different class instances.

    Verifies that two instances of the same class (A) are equal to each other,
    and that instances of different classes (A and B) are not equal.
    """
    a1, a2 = A(), A()
    assert a1 == a2

    a, b = A(), B()
    assert a != b


def test_extra_array() -> None:
    """Test equality comparison with dynamic array attributes.

    This test verifies that the equality operator works correctly when comparing
    objects that have array attributes added dynamically. It tests various scenarios
    including empty arrays, arrays with different lengths, and arrays with identical
    content.

    :raises AssertionError: If any equality comparison fails to match expected result.
    """
    a1, a2 = A(), A()
    assert a1 == a2

    a1.data = []  # type: ignore # pylint: disable=attribute-defined-outside-init
    assert a1 != a2

    a2.data = []  # type: ignore # pylint: disable=attribute-defined-outside-init
    assert a1 == a2

    for i in range(10):
        a1.data.append(i)  # type: ignore # pylint: disable=attribute-defined-outside-init
    assert a1 != a2

    for i in range(9):
        a2.data.append(i)  # type: ignore # pylint: disable=attribute-defined-outside-init
    assert a1 != a2

    a2.data.append(9)  # type: ignore # pylint: disable=attribute-defined-outside-init
    assert a1 == a2
