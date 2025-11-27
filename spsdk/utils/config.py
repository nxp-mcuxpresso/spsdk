#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK configuration management utilities.

This module provides a unified configuration framework for SPSDK applications,
including configuration validation, preprocessing hooks, and type-safe configuration
handling across the NXP MCU portfolio.
"""

import logging
import os
from abc import abstractmethod
from copy import deepcopy
from typing import Any, Optional, TypeVar, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError
from spsdk.utils.family import FamilyRevision
from spsdk.utils.misc import (
    find_file,
    load_configuration,
    load_hex_string,
    load_secret,
    value_to_bytes,
    value_to_int,
)
from spsdk.utils.schema_validator import check_config

logger = logging.getLogger(__name__)
_VT = TypeVar("_VT")


class Config(dict):
    """SPSDK Configuration Manager.

    This class extends Python's dictionary to provide enhanced configuration management
    for SPSDK operations. It supports nested key addressing using path separators,
    file-based configuration loading, and maintains context about configuration
    source and search paths.

    :cvar SEP: Path separator used for nested key addressing in configuration.
    """

    SEP = "/"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize configuration dictionary with default settings.

        Sets up a new configuration dictionary instance with default values for
        configuration directory (current working directory), empty configuration name,
        and empty search paths list.

        :param args: Variable length argument list passed to parent dictionary constructor.
        :param kwargs: Arbitrary keyword arguments passed to parent dictionary constructor.
        """
        super().__init__(*args, **kwargs)
        self.config_dir = os.getcwd()
        self.config_name = ""
        self.search_paths: list[str] = []

    @classmethod
    def create_from_file(cls, file_path: str) -> Self:
        """Create configuration object from file.

        Loads configuration data from the specified file path and initializes
        a new configuration object with proper search paths and metadata.

        :param file_path: Path to the configuration file to load.
        :return: Configuration object with loaded data and set search paths.
        """
        cfg_abs_path = os.path.abspath(file_path).replace("\\", "/")
        cfg = cls(load_configuration(cfg_abs_path))
        cfg_dir = os.path.dirname(cfg_abs_path)
        cfg_name = os.path.basename(cfg_abs_path)
        cfg.search_paths = [cfg_dir]
        cfg.config_dir = cfg_dir
        cfg.config_name = cfg_name
        return cfg

    @classmethod
    def get_path(cls, key: Union[str, int]) -> list:
        """Get keypath in list format.

        Converts a key (string or integer) into a list of path components. String keys are split
        by the separator and each component is converted to integer if possible, otherwise kept
        as string.

        :param key: Key to convert - either string path with separators or single integer.
        :return: List of path components as integers or strings.
        """
        ret: list[Union[int, str]] = []

        if isinstance(key, int):
            return [str(key)]
        for k in key.split(cls.SEP):
            try:
                ret.append(value_to_int(k))
            except SPSDKError:
                ret.append(k)
        return ret

    def get(self, key: str, defaults: Optional[Any] = None) -> Any:
        """Get configuration value with nested key support.

        Overrides the original dictionary get method to support nested addressing of items
        using '/' as a path separator.

        :param key: Key name including support of key path with '/'.
        :param defaults: Default value in case that item doesn't exist, defaults to None.
        :return: Configuration value or default if key not found.
        """
        try:
            return self.__getitem__(key)
        except SPSDKError:
            return defaults

    def __getitem__(self, key: str) -> Any:
        """Get configuration value by key path.

        Retrieves a value from the configuration using a dot-separated key path or a simple key.
        The method supports nested access to dictionaries and lists within the configuration.

        :param key: Configuration key or dot-separated path to nested value
        :raises SPSDKError: Invalid key path or unsupported data type in path
        :raises SPSDKKeyError: Key doesn't exist in configuration
        :return: Configuration value at the specified key path
        """

        def gets(source: Any, key_path: list) -> Any:
            """Get value from nested data structure using key path.

            Retrieves a value from a nested dictionary or list structure by following
            a sequence of keys. Supports both dictionary keys and list indices.

            :param source: The data structure to search in (dict or list).
            :param key_path: List of keys/indices defining the path to the desired value.
            :raises SPSDKError: Invalid key type for list access or unsupported source type.
            :raises SPSDKKeyError: Key doesn't exist in the data structure.
            :return: The value found at the specified key path.
            """
            key = key_path.pop(0)
            if isinstance(source, list):
                if not isinstance(key, int):
                    raise SPSDKError("Invalid key path - from list must be used number as key")
                ret = source[key]
            elif isinstance(source, dict):
                ret = dict.get(source, key)
            else:
                raise SPSDKError("Invalid configuration key path.")

            if ret is None:
                raise SPSDKKeyError(f"The {key} doesn't exists in {str(self)}")

            if len(key_path):
                return gets(ret, key_path)

            return ret

        try:
            return gets(self, self.get_path(key))
        except SPSDKKeyError:
            return gets(self, [key])

    def __setitem__(self, key: str, value: Any) -> None:
        """Set configuration value using dot-notation key path.

        This method allows setting nested configuration values using a dot-separated key path.
        It automatically creates intermediate dictionaries or lists as needed based on the
        key types in the path.

        :param key: Dot-separated key path (e.g., 'section.subsection.item').
        :param value: Value to set at the specified key path.
        :raises SPSDKError: Invalid configuration key path.
        """

        def sets(dest: Any, key_path: list, value: Any) -> None:
            """Set value in nested data structure using key path.

            Recursively traverses and modifies a nested data structure (dict/list) by following
            a key path. Creates intermediate containers as needed during traversal.

            :param dest: Target data structure to modify (dict or list).
            :param key_path: List of keys defining the path to the target location.
            :param value: Value to set at the target location.
            :raises SPSDKError: Invalid key type in configuration key path.
            """
            key = key_path.pop(0)

            if isinstance(key, int):
                if len(key_path) == 0:
                    dest[key] = value
                    return
                if key > len(dest):
                    dest[key] = []
                sets(dest[key], key_path, value)
            elif isinstance(key, str):
                if len(key_path) == 0:
                    dict.__setitem__(dest, key, value)
                    return
                if key not in dest:
                    dest[key] = {}
                sets(dest[key], key_path, value)
            else:
                raise SPSDKError("Invalid configuration key path.")

        sets(self, self.get_path(key), value)

    def get_input_file_name(self, key: str) -> str:
        """Get the absolute input file name.

        The method resolves the relative file path from configuration using the configured search paths
        to find the actual file location.

        :param key: Key path to config with input file name.
        :raises SPSDKError: Cannot find input file for the specified key.
        :return: The absolute path to input file.
        """
        try:
            return find_file(self[key], search_paths=self.search_paths)
        except SPSDKError as exc:
            raise SPSDKError(f"Cannot find input file for '{key}': {str(exc)}") from exc

    def get_output_file_name(self, key: str) -> str:
        """Get the absolute output file name.

        Resolves relative paths by joining them with the configuration directory path and converts
        the result to use forward slashes for consistency across platforms.

        :param key: Key path to config with output file name.
        :return: The absolute path to output file with forward slashes.
        """
        path = self[key]
        if os.path.isabs(path):
            return path
        return str(os.path.abspath(os.path.join(self.config_dir, path))).replace("\\", "/")

    def get_output_dir(self, key: str) -> str:
        """Get the absolute output directory.

        :param key: Key path to config with output directory.
        :return: The absolute path to output directory.
        """
        output_file_name = self.get_output_file_name(key)
        return os.path.dirname(output_file_name)

    def load_sub_config(self, key: str) -> "Config":
        """Load sub-configuration from a file path specified by the given key.

        The method resolves the file path using the current configuration's search paths,
        loads the configuration from that file, and extends the new configuration's
        search paths with the current ones.

        :param key: Configuration key containing the file path to load.
        :raises SPSDKError: When the file specified by the key cannot be found.
        :return: New Config instance loaded from the specified file.
        """
        try:
            path = find_file(self[key], search_paths=self.search_paths)
        except SPSDKError as exc:
            raise SPSDKError(f"Cannot find file for '{key}': {str(exc)}") from exc
        ret = self.create_from_file(path)
        ret.search_paths.extend(self.search_paths)
        return ret

    def get_list_of_configs(
        self, key: str, default: Optional[list["Config"]] = None
    ) -> list["Config"]:
        """Get list of sub configurations.

        The method retrieves a list of sub-configuration objects from the specified key.
        If the key doesn't exist and no default is provided, raises an exception.

        :param key: Key name of the list of sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: When the key is not found and no default value is provided.
        :return: List of sub configuration objects.
        """
        if key not in self:
            if default is not None:
                return default
            raise SPSDKError(f"The value is not in config at key: {key}")

        ret = []
        for i in range(len(self[key])):
            ret.append(self.get_config(f"{key}/{i}"))
        return ret

    def get_config(self, key: str, default: Optional["Config"] = None) -> "Config":
        """Get the key value as Config object.

        Retrieves a configuration value by key and converts it to a Config instance.
        The returned Config object inherits search paths and config directory from the parent.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKKeyError: The key is not found in configuration and no default provided.
        :return: Sub configuration as Config object.
        """
        cfg = self.get(key, default)
        if cfg is None:
            raise SPSDKKeyError(f"The value is not in config at key: {key}")
        ret = Config(cfg)
        ret.search_paths = self.search_paths
        ret.config_dir = self.config_dir

        return ret

    def get_dict(self, key: str, default: Optional[dict] = None) -> dict:
        """Get the key value as dictionary.

        Retrieves a configuration value for the specified key and ensures it is a dictionary type.
        If the value exists but is not a dictionary, an exception is raised.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the retrieved value is not a dictionary type.
        :return: Sub configuration as dictionary.
        """
        ret = self.get(key, default)
        if not isinstance(ret, dict):
            raise SPSDKError(f"The value is not dictionary at key: {key}")
        return ret

    def get_list(self, key: str, default: Optional[list] = None) -> list:
        """Get the key value as list.

        :param key: Key name of the configuration entry.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the value at the specified key is not a list.
        :return: Configuration value as list.
        """
        ret = self.get(key, default)
        if not isinstance(ret, list):
            raise SPSDKError(f"The value is not list at key: {key}")
        return ret

    def get_int(self, key: str, default: Optional[int] = None) -> int:
        """Get the key value as integer.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain it.
        :raises SPSDKError: The value is not integer at specified key.
        :return: Integer loaded from configuration.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The value is not integer at key: {key}")
        return value_to_int(ret)

    def get_bytes(self, key: str, default: Optional[bytes] = None) -> bytes:
        """Get the key value as bytes.

        The method retrieves a configuration value by key and converts it to bytes format.
        If the key is not found and no default is provided, an exception is raised.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: When the value cannot be converted to bytes or key is missing without default.
        :return: Bytes array loaded from configuration.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The value is not bytes at key: {key}")
        return value_to_bytes(ret, align_to_2n=False)

    def get_str(self, key: str, default: Optional[str] = None) -> str:
        """Get the key value as string.

        Retrieves the configuration value for the specified key and ensures it's a string type.
        If the value exists but is not a string, an exception is raised.

        :param key: Key name of the configuration entry.
        :param default: Default value to return if the key doesn't exist in configuration.
        :raises SPSDKError: If the retrieved value is not a string type.
        :return: Configuration value as string.
        """
        ret = self.get(key, default)
        if not isinstance(ret, str):
            raise SPSDKError(f"The value is not string at key: {key}")
        return ret

    def get_bool(self, key: str, default: Optional[bool] = None) -> bool:
        """Get the key value as boolean.

        Retrieves a configuration value for the specified key and ensures it is a boolean type.
        If the key is not found, returns the provided default value.

        :param key: Key name of the configuration entry.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the retrieved value is not a boolean type.
        :return: Boolean value from configuration.
        """
        ret = self.get(key, default)
        if not isinstance(ret, bool):
            raise SPSDKError(f"The value is not boolean at key: {key}")
        return ret

    def get_family(self) -> FamilyRevision:
        """Get the device family and revision from configuration.

        This method retrieves the family name and revision from the configuration data,
        defaulting to "latest" revision if not specified.

        :raises SPSDKValueError: If family is not specified in configuration.
        :return: FamilyRevision object representing device details.
        """
        family = self.get_str("family")
        revision = self.get_str("revision", default="latest")
        return FamilyRevision(family, revision)

    def load_symmetric_key(
        self,
        key: str,
        expected_size: int,
        default: Optional[bytes] = None,
        name: Optional[str] = "key",
    ) -> bytes:
        """Load symmetric key from configuration.

        The method loads a symmetric key from configuration that can be provided as:
        - File path to key file with hexadecimal value
        - File path to key file with binary value
        - Direct hexadecimal string value

        :param key: Configuration key name to retrieve the symmetric key.
        :param expected_size: Expected size of the key in bytes.
        :param default: Default value to use if the configuration key doesn't exist.
        :param name: Descriptive name for the key/data being loaded.
        :raises SPSDKError: If the configuration key doesn't exist and no default is provided.
        :return: Symmetric key as bytes.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The key '{key}' doesn't exists.")
        return load_hex_string(
            source=ret, expected_size=expected_size, search_paths=self.search_paths, name=name
        )

    def load_secret(self, key: str, default: Optional[str] = None) -> str:
        """Load secret text from the configuration value.

        There are several options how the secret is loaded from the input string:
        1. If the value is an existing path, first line of file is read and returned
        2. If the value has format '$ENV_VAR', the value of environment variable ENV_VAR is returned
        3. If the value has format '$ENV_VAR' and the value contains a valid path to a file,
           the first line of a file is returned
        4. If the value does not match any options above, the input value itself is returned
        Note, that the value with an initial component of ~ or ~user is replaced by that user's
        home directory.

        :param key: Key name of the configuration key.
        :param default: Default value if configuration doesn't contain the key.
        :raises SPSDKError: If the key doesn't exist and no default is provided.
        :return: The actual secret value.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The key '{key}' for secret doesn't exists.")
        return load_secret(value=ret, search_paths=self.search_paths)

    def check(self, schemas: list[dict[str, Any]], check_unknown_props: bool = False) -> None:
        """Check configuration against validation schemas.

        The method validates the current configuration object against provided schemas
        and optionally checks for unknown properties that might indicate configuration
        errors.

        :param schemas: List of validation schemas used in SPSDK.
        :param check_unknown_props: If True, check for unknown properties in config
            and print warnings.
        """
        check_config(
            self, schemas, search_paths=self.search_paths, check_unknown_props=check_unknown_props
        )


class PreValidationHook:
    """SPSDK pre-validation hook for register configuration processing.

    This abstract base class provides a framework for preprocessing register configurations
    before validation. It normalizes register and bitfield names to ensure consistent
    case-insensitive processing across different configuration formats.
    """

    def __init__(self, register_keys: Optional[list[str]] = None):
        """Initialize the hook with specific register keys to process.

        :param register_keys: List of keys in the config that contain register configurations.
                             If None, processes the entire config.
        """
        self.register_keys = register_keys or []

    def __call__(self, cfg: Config) -> Config:
        """Pre-validation hook for register configuration.

        This function converts all register names and bitfield names to uppercase
        to ensure case-insensitive matching during validation.

        :param cfg: Original configuration dictionary.
        :return: Modified configuration with uppercase register and bitfield keys.
        """
        # Create a deep copy of the original config
        result = deepcopy(cfg)

        if not self.register_keys:
            # Process the entire config
            self.process_registers(result)
        else:
            # Process only specified keys
            for key in self.register_keys:
                if key in result:
                    if isinstance(result[key], dict):
                        self.process_registers(result[key])

        return result

    @abstractmethod
    def process_registers(self, config: Config) -> None:
        """Process registers from the provided configuration.

        This method processes register configurations and applies them to the current
        instance state.

        :param config: Configuration object containing register settings to process.
        """
