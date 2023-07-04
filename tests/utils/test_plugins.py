#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
import sys

import pytest

from spsdk.exceptions import SPSDKError
from spsdk.utils.plugins import PluginsManager


@pytest.fixture
def plugin_cleanup() -> None:
    PluginsManager().plugins = {}


def test_plugin_manager_init(plugin_cleanup):
    pm = PluginsManager()
    assert pm.plugins == {}


def test_plugin_from_file_path(data_dir, plugin_cleanup):
    plugin_path = os.path.join(data_dir, "plugins", "custom_plugin.py")
    pm = PluginsManager()
    pm.load_from_source_file(plugin_path)
    assert len(pm.plugins) == 1
    assert list(pm.plugins.keys())[0] == "custom_plugin"
    klass = getattr(sys.modules["custom_plugin"], "CustomPlugin")
    assert klass is not None
    instance = klass()
    assert instance is not None


def test_plugin_from_file_path_non_existing(data_dir, plugin_cleanup):
    plugin_path = os.path.join(data_dir, "plugins", "non_existing.py")
    pm = PluginsManager()
    with pytest.raises(SPSDKError):
        pm.load_from_source_file(plugin_path)


def test_plugins_is_singleton(data_dir, plugin_cleanup):
    plugin_path = os.path.join(data_dir, "plugins", "custom_plugin.py")
    pm = PluginsManager()
    pm.load_from_source_file(plugin_path)
    assert len(pm.plugins) == 1
    same_instance = PluginsManager()
    assert len(same_instance.plugins) == 1
