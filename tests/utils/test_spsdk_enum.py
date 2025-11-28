#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SpsdkEnum utility tests.

This module contains comprehensive test cases for the SpsdkEnum class,
which provides enhanced enumeration functionality for SPSDK components.
"""

import pytest

from spsdk.exceptions import SPSDKKeyError
from spsdk.utils.spsdk_enum import SpsdkEnum


class SpsdkEnumNumbers(SpsdkEnum):
    """SPSDK test enumeration with numeric values.

    This enumeration class is used for testing SPSDK enum functionality with
    numbered entries that include labels and optional descriptions.
    """

    ONE = (1, "TheOne")
    TWO = (2, "TheTwo", "Just two.")
    THREE = (3, "TheThree")
    FOUR = (4, "TheFour", "Just four.")


class SpsdkEnumDays(SpsdkEnum):
    """SPSDK enumeration for weekdays testing.

    This class provides a test enumeration that extends SpsdkEnum with weekday
    values, used for testing SPSDK enumeration functionality and validation.
    """

    MONDAY = (1, "Monday")
    TUESDAY = (1, "Tuesday")


def test_simple_check() -> None:
    """Test basic functionality of SpsdkEnumNumbers tag values.

    Verifies that each enum member has the correct integer tag value
    assigned, ensuring proper enum initialization and value mapping.
    """
    assert SpsdkEnumNumbers.ONE.tag == 1
    assert SpsdkEnumNumbers.TWO.tag == 2
    assert SpsdkEnumNumbers.THREE.tag == 3
    assert SpsdkEnumNumbers.FOUR.tag == 4


def test_equals() -> None:
    """Test equality operations for SpsdkEnumNumbers enumeration.

    Verifies that enum members can be compared with their corresponding integer
    values and that inequality comparisons work correctly.

    :raises AssertionError: If any equality or inequality assertion fails.
    """
    assert SpsdkEnumNumbers.ONE == 1
    assert SpsdkEnumNumbers.TWO == 2
    assert SpsdkEnumNumbers.ONE != 2


def test_from_tag() -> None:
    """Test SpsdkEnumNumbers.from_tag() method functionality.

    Verifies that the from_tag() method correctly retrieves enum instances by their tag values,
    returns proper attributes (tag, label, description), and raises appropriate exceptions
    for invalid tag values.

    :raises SPSDKKeyError: When an invalid tag value is provided to from_tag().
    """
    two = SpsdkEnumNumbers.from_tag(2)
    assert two.tag == 2
    assert two.label == "TheTwo"
    assert two.description == "Just two."
    two = SpsdkEnumNumbers.from_tag(SpsdkEnumNumbers.TWO.tag)
    assert two.tag == 2
    assert two.label == "TheTwo"
    assert two.description == "Just two."
    with pytest.raises(SPSDKKeyError):
        SpsdkEnumNumbers.from_tag(10)


def test_from_name() -> None:
    """Test SpsdkEnumNumbers.from_label method functionality.

    Verifies that the from_label method correctly retrieves enum values by their
    label names and raises appropriate exceptions for invalid labels.

    :raises SPSDKKeyError: When attempting to retrieve a non-existent label.
    """
    two = SpsdkEnumNumbers.from_label("TheTwo")
    assert two.tag == 2
    assert two.label == "TheTwo"
    assert two.description == "Just two."
    with pytest.raises(SPSDKKeyError):
        SpsdkEnumNumbers.from_label("TEN")


def test_get_desc() -> None:
    """Test SpsdkEnumNumbers get_description method functionality.

    Validates the get_description method behavior including:
    - Retrieving descriptions for valid enum values and tags
    - Handling missing descriptions with and without default values
    - Proper exception raising for invalid inputs
    - Backwards compatibility requirements for error handling

    :raises SPSDKKeyError: When invalid enum values or string inputs are provided
    """
    assert SpsdkEnumNumbers.get_description(2) == "Just two."
    assert SpsdkEnumNumbers.get_description(SpsdkEnumNumbers.TWO.tag) == "Just two."
    assert SpsdkEnumNumbers.get_description(1) is None
    assert SpsdkEnumNumbers.get_description(SpsdkEnumNumbers.ONE.tag) is None
    assert SpsdkEnumNumbers.get_description(SpsdkEnumNumbers.ONE.tag, "Default") == "Default"
    assert SpsdkEnumNumbers.get_description(1, "Default") == "Default"
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description(10)
    # Backwards incompatible!!
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description(10, "default")
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description("ONE")  # type: ignore
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_description("TheTwo")  # type: ignore


def test_get_identifier() -> None:
    """Test SpsdkEnumNumbers get_label method functionality.

    Verifies that the get_label method correctly returns enum labels for valid
    numeric identifiers and enum tag values. Also tests that SPSDKKeyError
    is raised for invalid identifiers.

    :raises SPSDKKeyError: When an invalid identifier is provided to get_label method.
    """
    assert SpsdkEnumNumbers.get_label(1) == "TheOne"
    assert SpsdkEnumNumbers.get_label(SpsdkEnumNumbers.ONE.tag) == "TheOne"
    assert SpsdkEnumNumbers.get_label(2) == "TheTwo"
    assert SpsdkEnumNumbers.get_label(SpsdkEnumNumbers.TWO.tag) == "TheTwo"
    with pytest.raises(SPSDKKeyError):
        assert SpsdkEnumNumbers.get_label(10)


def test_contains() -> None:
    """Test containment operations for SpsdkEnum values.

    Verifies that SpsdkEnum values can be properly checked for containment
    within the enum class itself and within various container types. Tests
    both positive and negative containment scenarios including membership
    in lists with mixed types.
    """
    assert SpsdkEnumNumbers.ONE in SpsdkEnumNumbers
    assert not SpsdkEnumNumbers.ONE not in SpsdkEnumNumbers
    assert SpsdkEnumNumbers.TWO in SpsdkEnumNumbers
    assert SpsdkEnumNumbers.ONE in [SpsdkEnumNumbers.ONE]
    assert 1 in [SpsdkEnumNumbers.ONE]
    assert 1 in [5, SpsdkEnumNumbers.ONE]
    assert 2 not in [5, SpsdkEnumNumbers.ONE]
    assert 2 in [SpsdkEnumNumbers.ONE, SpsdkEnumNumbers.TWO]


def test_enum_len() -> None:
    """Test that SpsdkEnumNumbers enum has the expected number of items.

    Verifies that the SpsdkEnumNumbers enumeration contains exactly 4 members,
    ensuring the enum structure is maintained correctly.
    """
    assert len(SpsdkEnumNumbers) == 4


def test_enum_get_item() -> None:
    """Test enum item access using dictionary-like syntax.

    Verifies that SpsdkEnumNumbers can be accessed using square bracket notation
    with string keys, and that accessing non-existent keys raises KeyError.

    :raises KeyError: When accessing non-existent enum key.
    """
    value = SpsdkEnumNumbers["ONE"]
    assert value.label == "TheOne"
    with pytest.raises(KeyError):
        assert SpsdkEnumNumbers["TEN"]


def test_enum_contains() -> None:
    """Test the contains method of SpsdkEnumNumbers enum.

    Verifies that the contains method correctly identifies valid enum values
    by both name and numeric value, and properly rejects invalid values.

    :raises AssertionError: If any of the contains method calls return unexpected results.
    """
    assert SpsdkEnumNumbers.contains("TheOne")
    assert SpsdkEnumNumbers.contains(1)
    assert SpsdkEnumNumbers.contains("TheTwo")
    assert SpsdkEnumNumbers.contains(2)
    assert not SpsdkEnumNumbers.contains("Whatever")
    assert not SpsdkEnumNumbers.contains(10)


def test_enum_isinstance() -> None:
    """Test isinstance functionality for SpsdkEnum classes.

    Verifies that SpsdkEnum instances correctly identify as instances of their
    own enum class but not as instances of other enum classes or base types.
    Tests both positive and negative isinstance checks to ensure proper type
    checking behavior.
    """
    assert isinstance(SpsdkEnumNumbers.ONE, SpsdkEnumNumbers)
    assert isinstance(SpsdkEnumNumbers.TWO, SpsdkEnumNumbers)
    assert not isinstance(SpsdkEnumNumbers.ONE, SpsdkEnumDays)
    assert not isinstance(1, SpsdkEnumDays)
