#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Configuration object used in SPSDK."""

import logging
import os
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
    """Class keeping configuration of SPSDK features."""

    SEP = "/"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Config dictionary constructor."""
        super().__init__(*args, **kwargs)
        self.config_dir = os.getcwd()
        self.config_name = ""
        self.search_paths: list[str] = []

    @classmethod
    def create_from_file(cls, file_path: str) -> Self:
        """Create the configuration from the file.

        :param file_path: File path of the configuration
        :return: Configuration object
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
        """Get keypath in list."""
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
        """Overriding the original dictionary to support nested addressing of items.

        :param key: Key name  including support of key path with '/'.
        :param defaults: Default value in case that item doesn't exists, defaults to None
        :return: Value
        """
        try:
            return self.__getitem__(key)
        except SPSDKError:
            return defaults

    def __getitem__(self, key: str) -> Any:

        def gets(source: Any, key_path: list) -> Any:
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

        def sets(dest: Any, key_path: list, value: Any) -> None:
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

        :param key: Key path to config with input file name.
        :return The absolute path to input file.
        """
        try:
            return find_file(self[key], search_paths=self.search_paths)
        except SPSDKError as exc:
            raise SPSDKError(f"Cannot find input file for '{key}': {str(exc)}") from exc

    def get_output_file_name(self, key: str) -> str:
        """Get the absolute output file name.

        :param key: Key path to config with input file name.
        :return The absolute path to input file.
        """
        path = self[key]
        if os.path.isabs(path):
            return path
        return str(os.path.abspath(os.path.join(self.config_dir, path))).replace("\\", "/")

    def get_output_dir(self, key: str) -> str:
        """Get the absolute output directory.

        :param key: Key path to config with output directory.
        :return The absolute path to output directory.
        """
        output_file_name = self.get_output_file_name(key)
        return os.path.dirname(output_file_name)

    def load_sub_config(self, key: str) -> "Config":
        """Get sub configuration."""
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

        :param key: Key name of the list of sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: List of sub configuration
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
        """Get the key value as Config.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Sub configuration
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

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Sub configuration
        """
        ret = self.get(key, default)
        if not isinstance(ret, dict):
            raise SPSDKError(f"The value is not dictionary at key: {key}")
        return ret

    def get_list(self, key: str, default: Optional[list] = None) -> list:
        """Get the key value as dictionary.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Sub configuration
        """
        ret = self.get(key, default)
        if not isinstance(ret, list):
            raise SPSDKError(f"The value is not list at key: {key}")
        return ret

    def get_int(self, key: str, default: Optional[int] = None) -> int:
        """Get the key value as integer.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Integer loaded from configuration
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The value is not integer at key: {key}")
        return value_to_int(ret)

    def get_bytes(self, key: str, default: Optional[bytes] = None) -> bytes:
        """Get the key value as bytes.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Bytes array loaded from configuration
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The value is not bytes at key: {key}")
        return value_to_bytes(ret, align_to_2n=False)

    def get_str(self, key: str, default: Optional[str] = None) -> str:
        """Get the key value as string.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Sub configuration
        """
        ret = self.get(key, default)
        if not isinstance(ret, str):
            raise SPSDKError(f"The value is not string at key: {key}")
        return ret

    def get_bool(self, key: str, default: Optional[bool] = None) -> bool:
        """Get the key value as boolean.

        :param key: Key name of the sub configuration.
        :param default: Default value if configuration doesn't contains it.
        :return: Sub configuration
        """
        ret = self.get(key, default)
        if not isinstance(ret, bool):
            raise SPSDKError(f"The value is not boolean at key: {key}")
        return ret

    def get_family(self) -> FamilyRevision:
        """Get the device family and revision from configuration.

        :return: FamilyRevision object representing device details
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
        """Get the HEX string from the configuration by key.

        Note: The value could be:
            - File path to key file with hex value
            - File path to key file with binary value
            - Hexadecimal value.

        :param key: Key name of the key.
        :param expected_size: Expected size of key in bytes.
        :param default: Default value if configuration doesn't contains it.
        :param name: Name for the key/data to load
        :return: Key in bytes.
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The key '{key}' doesn't exists.")
        return load_hex_string(
            source=ret, expected_size=expected_size, search_paths=self.search_paths, name=name
        )

    def load_secret(self, key: str, default: Optional[str] = None) -> str:
        """Load secret text from the configuration value.

        There are several options how the secret is loaded from the input string
        1. If the value is an existing path, first line of file is read and returned
        2. If the value has format '$ENV_VAR', the value of environment variable ENV_VAR is returned
        3. If the value has format '$ENV_VAR' and the value contains a valid path to a file,
        the first line of a file is returned
        4. If the value does not match any options above, the input value itself is returned

        Note, that the value with an initial component of ~ or ~user is replaced by that user's home directory.

        :param key: Key name of the key.
        :param default: Default value if configuration doesn't contains it.
        :return: The actual secret value
        """
        ret = self.get(key, default)
        if ret is None:
            raise SPSDKError(f"The key '{key}' for secret doesn't exists.")
        return load_secret(value=ret, search_paths=self.search_paths)

    def check(self, schemas: list[dict[str, Any]], check_unknown_props: bool = False) -> None:
        """Check configuration against validation schemas.

        :param schemas: List of validation schemas used in SPSDK.
        :param check_unknown_props: If True, check for unknown properties in config and print warnings
        """
        check_config(
            self, schemas, search_paths=self.search_paths, check_unknown_props=check_unknown_props
        )
