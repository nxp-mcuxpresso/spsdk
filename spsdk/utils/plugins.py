#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK plugins manager for dynamic module loading and management.

This module provides functionality for discovering, loading, and managing
plugins within the SPSDK framework. It supports dynamic plugin discovery
from specified directories and handles plugin lifecycle management.
"""

import logging
import os
import sys
from importlib.machinery import ModuleSpec
from importlib.util import find_spec, module_from_spec, spec_from_file_location
from types import ModuleType
from typing import Optional

import importlib_metadata

from spsdk.exceptions import SPSDKError, SPSDKTypeError
from spsdk.utils.misc import SingletonMeta
from spsdk.utils.spsdk_enum import SpsdkEnum

logger = logging.getLogger(__name__)


class PluginType(SpsdkEnum):
    """SPSDK Plugin Type Enumeration.

    This enumeration defines the available plugin types supported by SPSDK, including
    signature providers, device interfaces, debug probes, and other extensible components.
    Each plugin type contains an identifier, entry point name, and human-readable description.
    """

    SIGNATURE_PROVIDER = (0, "spsdk.sp", "Signature provider")
    DEVICE_INTERFACE = (1, "spsdk.device.interface", "Device interface")
    DEBUG_PROBE = (2, "spsdk.debug_probe", "Debug Probe")
    WPC_SERVICE = (3, "spsdk.wpc.service", "WPC Service")
    SB31_KEY_DERIVATOR = (4, "spsdk.sb31kdp", "Key Derivator for SB31 encryption")
    PUBLIC_KEY_PROVIDER = (5, "spsdk.pkp", "Public Key Provider")


class PluginsManager(metaclass=SingletonMeta):
    """SPSDK Plugin Manager for dynamic module loading and registration.

    This singleton class manages the loading, registration, and retrieval of plugins
    from various sources including setuptools entry points, Python source files,
    and module names. It provides a centralized system for extending SPSDK
    functionality through dynamically loaded modules.
    """

    def __init__(self) -> None:
        """Initialize the plugin manager.

        Creates an empty dictionary to store loaded plugins where keys are plugin
        names and values are the corresponding module objects.
        """
        self.plugins: dict[str, ModuleType] = {}

    def load_from_entrypoints(self, group_name: Optional[str] = None) -> int:
        """Load modules from given setuptools group.

        The method loads plugins from setuptools entry points for the specified group name.
        If no group name is provided, it loads from all available plugin type groups.
        Failed module imports are logged as warnings and skipped.

        :param group_name: Entry point group to load plugins from. If None, loads from all groups.
        :raises SPSDKTypeError: When group_name is not a string type.
        :return: The number of successfully loaded plugins.
        """
        if group_name is not None and not isinstance(group_name, str):
            raise SPSDKTypeError("Group name must be of string type.")
        group_names = (
            [group_name]
            if group_name is not None
            else [PluginType.get_label(tag) for tag in PluginType.tags()]
        )

        entry_points: list[importlib_metadata.EntryPoint] = []
        for group in group_names:
            eps = importlib_metadata.entry_points(group=group)
            entry_points.extend(eps)

        count = 0
        for ep in entry_points:
            try:
                plugin = ep.load()
            except (ModuleNotFoundError, ImportError) as exc:
                logger.warning(f"Module {ep.module} could not be loaded: {exc}")
                continue
            if self.register(plugin):
                logger.info(f"Plugin {ep.name}-{ep.group} has been loaded.")
                count += 1
        return count

    def load_from_source_file(self, source_file: str, module_name: Optional[str] = None) -> None:
        """Import Python source file directly.

        The method loads a Python source file as a module and registers it with the plugin system.
        It creates a module specification from the file location and imports it dynamically.

        :param source_file: Path to python source file: absolute or relative to cwd
        :param module_name: Name for the new module, default is basename of the source file
        :raises SPSDKError: If importing of source file failed
        """
        name = module_name or os.path.splitext(os.path.basename(source_file))[0]
        spec = spec_from_file_location(name=name, location=source_file)
        if not spec:
            raise SPSDKError(
                f"Source '{source_file}' does not exist. Check if it is valid file path name"
            )

        module = self._import_module_spec(spec)
        self.register(module)

    def load_from_module_name(self, module_name: str) -> None:
        """Import Python module directly by name and register it.

        The method uses importlib to find and import a Python module by its name,
        then registers it with the plugin system.

        :param module_name: Name of the Python module to be imported and registered.
        :raises SPSDKError: If the module cannot be found or importing fails.
        """
        spec = find_spec(name=module_name)
        if not spec:
            raise SPSDKError(
                f"Source '{module_name}' does not exist.Check if it is valid file module name"
            )
        module = self._import_module_spec(spec)
        self.register(module)

    def _import_module_spec(self, spec: ModuleSpec) -> ModuleType:
        """Import module from module specification.

        Loads a module from the provided module specification and registers it in the
        system modules registry for future use.

        :param spec: Module specification containing loader and module metadata.
        :raises SPSDKError: Failed to load or execute the module specification.
        :return: Successfully imported and executed module.
        """
        module = module_from_spec(spec)
        try:
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)  # type: ignore
            logger.debug(f"A module spec {spec.name} has been loaded.")
        except Exception as e:
            raise SPSDKError(f"Failed to load module spec {spec.name}: {e}") from e
        return module

    def register(self, plugin: ModuleType) -> bool:
        """Register a plugin with the given name.

        :param plugin: Plugin as a module to be registered.
        :return: True if plugin was successfully registered, False if plugin is already registered.
        """
        plugin_name = self.get_plugin_name(plugin)
        if plugin_name in self.plugins:
            logger.debug(f"Plugin {plugin_name} has been already registered.")
            return False
        self.plugins[plugin_name] = plugin
        logger.debug(f"A plugin {plugin_name} has been registered.")
        return True

    def get_plugin(self, name: str) -> Optional[ModuleType]:
        """Get plugin by name from registered plugins.

        :param name: Name of the plugin to retrieve.
        :return: Plugin module if found, None if plugin with given name is not registered.
        """
        return self.plugins.get(name)

    def get_plugin_name(self, plugin: ModuleType) -> str:
        """Get canonical name of plugin.

        The method extracts the module name from the plugin object and validates
        that the name can be determined.

        :param plugin: Plugin as a module
        :raises SPSDKError: Plugin name could not be determined.
        :return: String with plugin name
        """
        name = getattr(plugin, "__name__", None)
        if name is None:
            raise SPSDKError("Plugin name could not be determined.")
        return name
