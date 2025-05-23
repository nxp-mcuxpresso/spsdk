#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


from spsdk.utils.config import Config


def test_config_basic():
    """Test of basic functionalities."""
    cfg = Config()
    cfg["test"] = 1
    assert 1 == cfg["test"]
    assert 1 == cfg.get("test")


def test_config_basic2():
    """Test of basic functionalities."""
    cfg = Config({"test": 1})
    assert 1 == cfg["test"]
    assert 1 == cfg.get("test")


def test_config_nested_get():
    """Test of nested key path get functionalities."""
    cfg = Config()
    # test get nested dict
    cfg["test"] = {"test_1": "nested_1"}
    assert "nested_1" == cfg["test"]["test_1"]
    assert "nested_1" == cfg["test/test_1"]
    assert "nested_1" == cfg.get("test/test_1")


def test_config_nested_set():
    """Test of nested key path set functionalities."""
    cfg = Config()

    # Test set item
    cfg["test/test_2"] = "test_2"
    assert "test_2" == cfg["test"]["test_2"]
    assert "test_2" == cfg["test/test_2"]
    assert "test_2" == cfg.get("test/test_2")


def test_config_nested_get_list():
    """Test of nested key path get functionalities."""
    cfg = Config()
    cfg["array"] = ["array_0", "array_1"]
    assert "array_0" == cfg["array"][0]
    assert "array_1" == cfg["array"][1]
    assert "array_0" == cfg["array/0"]
    assert "array_1" == cfg["array/1"]
    assert "array_1" == cfg.get("array/1")


def test_config_nested_set_list():
    """Test of nested key path get functionalities."""
    cfg = Config()
    cfg["array/0"] = "array_0"
    cfg["array/1"] = "array_1"
    assert "array_0" == cfg["array"][0]
    assert "array_1" == cfg["array"][1]
    assert "array_0" == cfg["array/0"]
    assert "array_1" == cfg["array/1"]
    assert "array_1" == cfg.get("array/1")
