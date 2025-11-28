#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK Configuration utility tests.

This module contains unit tests for the SPSDK Config class functionality,
including basic configuration operations, nested value access, and list handling.
"""

from spsdk.utils.config import Config


def test_config_basic() -> None:
    """Test basic Config class functionality.

    Verifies that the Config class can store and retrieve values using both
    dictionary-style access and the get() method.

    :raises AssertionError: If the stored value doesn't match the expected value.
    """
    cfg = Config()
    cfg["test"] = 1
    assert 1 == cfg["test"]
    assert 1 == cfg.get("test")


def test_config_basic2() -> None:
    """Test basic Config class functionality with dictionary initialization.

    Verifies that a Config object can be properly initialized with a dictionary
    and that values can be accessed using both dictionary-style indexing and
    the get() method.
    """
    cfg = Config({"test": 1})
    assert 1 == cfg["test"]
    assert 1 == cfg.get("test")


def test_config_nested_get() -> None:
    """Test nested key path get functionalities for Config class.

    Validates that the Config class properly handles nested dictionary access
    using both traditional bracket notation and path-based string notation
    with forward slash separators.
    """
    cfg = Config()
    # test get nested dict
    cfg["test"] = {"test_1": "nested_1"}
    assert "nested_1" == cfg["test"]["test_1"]
    assert "nested_1" == cfg["test/test_1"]
    assert "nested_1" == cfg.get("test/test_1")


def test_config_nested_set() -> None:
    """Test nested key path set functionality in Config class.

    Validates that the Config class properly handles setting values using nested
    key paths with forward slash notation and retrieval through multiple access
    methods including dictionary-style access and get() method.
    """
    cfg = Config()

    # Test set item
    cfg["test/test_2"] = "test_2"
    assert "test_2" == cfg["test"]["test_2"]
    assert "test_2" == cfg["test/test_2"]
    assert "test_2" == cfg.get("test/test_2")


def test_config_nested_get_list() -> None:
    """Test nested key path get functionalities for Config class.

    Verifies that Config objects support both standard list indexing and
    path-based access using forward slash notation for nested elements.
    Tests array access through direct indexing, path notation, and the
    get method to ensure consistent behavior across different access patterns.
    """
    cfg = Config()
    cfg["array"] = ["array_0", "array_1"]
    assert "array_0" == cfg["array"][0]
    assert "array_1" == cfg["array"][1]
    assert "array_0" == cfg["array/0"]
    assert "array_1" == cfg["array/1"]
    assert "array_1" == cfg.get("array/1")


def test_config_nested_set_list() -> None:
    """Test nested key path set and get functionalities for list operations.

    Validates that Config class properly handles nested key paths when setting
    and retrieving list elements using both slash notation and direct indexing.
    The test verifies that array elements can be set using path notation and
    accessed through multiple methods.
    """
    cfg = Config()
    cfg["array/0"] = "array_0"
    cfg["array/1"] = "array_1"
    assert "array_0" == cfg["array"][0]
    assert "array_1" == cfg["array"][1]
    assert "array_0" == cfg["array/0"]
    assert "array_1" == cfg["array/1"]
    assert "array_1" == cfg.get("array/1")
