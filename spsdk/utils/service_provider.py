#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Service Provider module for SPSDK utility classes."""

import abc
import inspect
import logging
from typing import Any, Iterator, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.utils.plugins import PluginsManager

logger = logging.getLogger(__name__)


class ServiceProvider(abc.ABC):
    """Service Provider abstract class.

    This class serves as a base class for various service providers in the SPSDK framework.
    It provides functionality for managing and creating service provider instances, handling
    parameters, and plugin management.

    Class Attributes:
        legacy_identifier_name (str): Name of the legacy identifier attribute
        identifier (str): Unique identifier for the service provider
        plugin_identifier (str): Identifier used for plugin management
        reserved_keys (list): List of reserved parameter keys

    The class implements a plugin system and parameter handling for service providers.
    It supports both modern and legacy identifier systems, with automatic conversion
    from legacy to modern format.
    """

    legacy_identifier_name: str
    identifier: str
    plugin_identifier: str
    reserved_keys = ["type"]

    def __init_subclass__(cls) -> None:
        if not inspect.isabstract(cls) and hasattr(cls, cls.legacy_identifier_name):
            identifier = getattr(cls, cls.legacy_identifier_name)
            logger.warning(
                (
                    f"Class {cls.__name__} uses legacy identifier '{cls.legacy_identifier_name} = {identifier}', "
                    f"please use 'identifier = {identifier}' instead"
                )
            )
            setattr(cls, "identifier", getattr(cls, cls.legacy_identifier_name))

        if not inspect.isabstract(cls) and not hasattr(cls, "identifier"):
            raise SPSDKError(f"{cls.__name__}.identifier is not set")
        return super().__init_subclass__()

    def info(self) -> str:
        """Provide information about the Service provider."""
        return self.__class__.__name__

    @classmethod
    def get_types(cls, include_abstract: bool = False) -> list[str]:
        """Returns a list of all available signature provider types."""
        return [
            sub_class.identifier
            for sub_class in cls.get_all_providers(include_abstract=include_abstract)
        ]

    @classmethod
    def filter_params(cls, klass: Type[Self], params: dict[str, str]) -> dict[str, str]:
        """Remove unused parameters from the given dictionary based on the class constructor.

        :param klass: Service provider class.
        :param params: Dictionary of parameters.
        :return: Filtered dictionary of parameters.
        """
        unused_params = set(params) - set(klass.__init__.__code__.co_varnames)
        for key in cls.reserved_keys:
            if key in unused_params:
                del params[key]
        return params

    @staticmethod
    def convert_params(params: str) -> dict[str, str]:
        """Coverts creation params from string into dictionary.

        e.g.: "type=file;file_path=some_path" -> {'type': 'file', 'file_path': 'some_path'}
        :param params: Params in the mentioned format.
        :raises: SPSDKKeyError: Duplicate key found.
        :raises: SPSDKValueError: Parameter must meet the following pattern: type=file;file_path=some_path.
        :return: Converted dictionary of parameters.
        """
        result: dict[str, str] = {}
        try:
            for p in params.split(";"):
                key, value = p.split("=")

                # Check for duplicate keys
                if key in result:
                    raise SPSDKKeyError(f"Duplicate key found: {key}")

                result[key] = value

        except ValueError as e:
            raise SPSDKValueError(
                "Parameter must meet the following pattern: type=file;file_path=some_path"
            ) from e

        return result

    @classmethod
    def create(cls, params: Union[str, dict]) -> Optional[Self]:
        """Creates an concrete instance of signature provider."""
        cls.load_plugins()
        if isinstance(params, str):
            params = cls.convert_params(params)
        sp_classes = cls.get_all_providers()
        for klass in sp_classes:  # pragma: no branch  # there always be at least one subclass
            if klass.identifier == params["type"]:
                klass.filter_params(klass, params)
                return klass(**params)

        logger.info(f"{cls.__name__} of type {params['type']} was not found.")
        return None

    @classmethod
    def load_plugins(cls) -> None:
        """Load all plugins implementing this service.

        This method checks if the class has a plugin_identifier and uses the PluginsManager
        to dynamically load plugins from entry points associated with that identifier.
        """
        if hasattr(cls, "plugin_identifier"):
            logger.info(f"Loading plugins: {cls.plugin_identifier}")
            manager = PluginsManager()
            manager.load_from_entrypoints(cls.plugin_identifier)

    @classmethod
    def get_all_providers(cls, include_abstract: bool = False) -> list[Type[Self]]:
        """Get list of all available signature providers."""

        def get_subclasses(
            base_class: Type[Self],
        ) -> Iterator[Type[Self]]:
            """Recursively find all subclasses."""
            for subclass in base_class.__subclasses__():
                yield subclass
                yield from get_subclasses(subclass)

        if include_abstract:
            return list(get_subclasses(cls))
        return list(filter(lambda x: not inspect.isabstract(x), get_subclasses(cls)))

    @classmethod
    def get_provider(cls, identifier: str) -> Type[Self]:
        """Get provider class with given identifier."""
        for provider in cls.get_all_providers():
            if provider.identifier == identifier:
                return provider
        raise SPSDKValueError(f"No provider with identifier '{identifier}' was found")

    @classmethod
    def create_ex(
        cls,
        service_config: Optional[str] = None,
        local_provider: Optional[Type[Self]] = None,
        local_file: Optional[str] = None,
        search_paths: Optional[list[str]] = None,
        **kwargs: Any,
    ) -> Self:
        """Create instance of a Service Provider with external providers."""
        if service_config:
            params = cls.convert_params(service_config)
            params.update(**kwargs)
            provider = cls.create(params=params)
        elif local_file and local_provider:
            provider = local_provider(local_file=local_file, search_paths=search_paths)  # type: ignore[call-arg]
        else:
            raise SPSDKError("No key derivator configuration is provided")

        if not provider:
            raise SPSDKError(
                f"Cannot create signature provider from: {service_config or local_file}"
            )

        return provider
