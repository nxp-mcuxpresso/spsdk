#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Plugin system unit tests.

This module contains comprehensive unit tests for the SPSDK plugin management
system, verifying plugin loading, initialization, and singleton behavior.
"""

import os
import sys
from typing import Any

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.utils.plugins import PluginsManager


@pytest.fixture
def plugin_cleanup() -> None:
    """Clean up all loaded plugins from the PluginsManager.

    This method resets the plugins dictionary in the PluginsManager singleton,
    effectively removing all previously loaded plugins. Typically used in test
    cleanup to ensure a clean state between test runs.
    """
    PluginsManager().plugins = {}


def test_plugin_manager_init(plugin_cleanup: Any) -> None:  # pylint: disable=redefined-outer-name
    """Test plugin manager initialization.

    Verifies that a newly created PluginsManager instance has an empty
    plugins dictionary.

    :param plugin_cleanup: Fixture for cleaning up plugin state after test.
    """
    pm = PluginsManager()
    assert pm.plugins == {}


def test_plugin_from_file_path(  # pylint: disable=redefined-outer-name
    data_dir: str, plugin_cleanup: Any
) -> None:
    """Test plugin loading from file path.

    Verifies that the PluginsManager can successfully load a plugin from a source file,
    register it correctly, and instantiate the plugin class.

    :param data_dir: Directory path containing test data files.
    :param plugin_cleanup: Fixture for cleaning up loaded plugins after test.
    """
    plugin_path = os.path.join(data_dir, "plugins", "custom_plugin.py")
    pm = PluginsManager()
    pm.load_from_source_file(plugin_path)
    assert len(pm.plugins) == 1
    assert list(pm.plugins.keys())[0] == "custom_plugin"
    klass = getattr(sys.modules["custom_plugin"], "CustomPlugin")
    assert klass is not None
    instance = klass()
    assert instance is not None


def test_plugin_from_file_path_non_existing(  # pylint: disable=redefined-outer-name
    data_dir: str, plugin_cleanup: Any
) -> None:
    """Test loading a plugin from a non-existing file path.

    Verifies that the PluginsManager correctly raises an SPSDKError when attempting
    to load a plugin from a file path that does not exist.

    :param data_dir: Path to the test data directory containing plugin files.
    :param plugin_cleanup: Fixture for cleaning up plugin state after test execution.
    :raises SPSDKError: Expected exception when plugin file does not exist.
    """
    plugin_path = os.path.join(data_dir, "plugins", "non_existing.py")
    pm = PluginsManager()
    with pytest.raises(SPSDKError):
        pm.load_from_source_file(plugin_path)


def test_plugins_is_singleton(  # pylint: disable=redefined-outer-name
    data_dir: str, plugin_cleanup: Any
) -> None:
    """Test that PluginsManager follows singleton pattern.

    Verifies that multiple instances of PluginsManager share the same state,
    ensuring that plugins loaded in one instance are accessible from another
    instance of the same class.

    :param data_dir: Directory path containing test data files.
    :param plugin_cleanup: Fixture for cleaning up plugin state after test.
    """
    plugin_path = os.path.join(data_dir, "plugins", "custom_plugin.py")
    pm = PluginsManager()
    pm.load_from_source_file(plugin_path)
    assert len(pm.plugins) == 1
    same_instance = PluginsManager()
    assert len(same_instance.plugins) == 1
