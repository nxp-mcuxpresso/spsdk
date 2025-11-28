#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Service Provider base class for implementing provider pattern.

This module provides an abstract base class for implementing the service provider
pattern across SPSDK components, enabling flexible service registration and discovery.
"""

import abc
import inspect
import logging
from typing import Any, Iterator, Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError, SPSDKKeyError, SPSDKValueError
from spsdk.utils.plugins import PluginsManager

logger = logging.getLogger(__name__)


class ServiceProvider(abc.ABC):
    """Service Provider abstract base class for SPSDK framework.

    This class serves as a foundation for implementing various service providers within
    the SPSDK ecosystem. It provides a plugin system with automatic discovery and
    registration, parameter handling, and factory methods for creating service provider
    instances. The class supports both modern and legacy identifier systems with
    automatic migration warnings.

    :cvar reserved_keys: List of parameter keys reserved by the framework.
    """

    legacy_identifier_name: str
    identifier: str
    plugin_identifier: str
    reserved_keys = ["type"]

    def __init_subclass__(cls) -> None:
        """Initialize subclass with identifier validation and legacy support.

        Validates that concrete subclasses have an 'identifier' attribute set and handles
        legacy identifier names with deprecation warnings. Abstract classes are skipped
        from validation.

        :raises SPSDKError: When concrete subclass doesn't have 'identifier' attribute set.
        """
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
        """Provide information about the Service provider.

        :return: Name of the service provider class.
        """
        return self.__class__.__name__

    @classmethod
    def get_types(cls, include_abstract: bool = False) -> list[str]:
        """Get all available signature provider types.

        Returns a list of identifiers for all signature provider classes that are
        currently registered in the system.

        :param include_abstract: Whether to include abstract provider types in the result.
        :return: List of signature provider type identifiers.
        """
        return [
            sub_class.identifier
            for sub_class in cls.get_all_providers(include_abstract=include_abstract)
        ]

    @classmethod
    def filter_params(cls, klass: Type[Self], params: dict[str, str]) -> dict[str, str]:
        """Filter unused parameters from dictionary based on class constructor.

        Removes parameters that are not accepted by the class constructor's __init__ method,
        while preserving reserved keys that should be filtered out.

        :param klass: Service provider class to check constructor parameters against.
        :param params: Dictionary of string parameters to filter.
        :return: Filtered dictionary containing only valid constructor parameters.
        """
        unused_params = set(params) - set(klass.__init__.__code__.co_varnames)
        for key in cls.reserved_keys:
            if key in unused_params:
                del params[key]
        return params

    @staticmethod
    def convert_params(params: str) -> dict[str, str]:
        """Convert creation params from string into dictionary.

        The method parses a semicolon-separated string of key-value pairs into a dictionary.
        Each pair should be in the format "key=value".

        :param params: Semicolon-separated string of key-value pairs (e.g., "type=file;file_path=path").
        :raises SPSDKKeyError: Duplicate key found in the parameters.
        :raises SPSDKValueError: Parameter format is invalid, must follow "key=value;key=value" pattern.
        :return: Dictionary containing the parsed key-value pairs.
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
        """Create a concrete instance of signature provider.

        Loads available plugins and creates an instance of the appropriate signature provider
        based on the provided parameters. The method searches through all registered provider
        classes to find one matching the specified type.

        :param params: Either a string identifier or dictionary containing provider configuration.
                       Dictionary must include 'type' key specifying the provider identifier.
        :return: Instance of the matching signature provider class, or None if not found.
        """
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

        :param cls: The class to load plugins for.
        """
        if hasattr(cls, "plugin_identifier"):
            logger.info(f"Loading plugins: {cls.plugin_identifier}")
            manager = PluginsManager()
            manager.load_from_entrypoints(cls.plugin_identifier)

    @classmethod
    def get_all_providers(cls, include_abstract: bool = False) -> list[Type[Self]]:
        """Get list of all available signature providers.

        The method recursively searches through all subclasses of the current class to find
        signature provider implementations.

        :param include_abstract: Whether to include abstract classes in the result.
        :return: List of all signature provider classes found in the inheritance hierarchy.
        """

        def get_subclasses(
            base_class: Type[Self],
        ) -> Iterator[Type[Self]]:
            """Recursively find all subclasses of the given base class.

            This method traverses the inheritance hierarchy to discover all direct and indirect
            subclasses of the specified base class using depth-first search.

            :param base_class: The base class to find subclasses for.
            :return: Iterator yielding all subclasses of the base class.
            """
            for subclass in base_class.__subclasses__():
                yield subclass
                yield from get_subclasses(subclass)

        if include_abstract:
            return list(get_subclasses(cls))
        return list(filter(lambda x: not inspect.isabstract(x), get_subclasses(cls)))

    @classmethod
    def get_provider(cls, identifier: str) -> Type[Self]:
        """Get provider class with given identifier.

        Searches through all available providers and returns the one that matches
        the specified identifier.

        :param identifier: String identifier of the provider to find.
        :raises SPSDKValueError: When no provider with the given identifier exists.
        :return: Provider class that matches the identifier.
        """
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
        """Create instance of a Service Provider with external providers.

        This method provides flexible creation of service providers either from configuration
        strings or from local provider classes with file paths.

        :param service_config: Configuration string for service provider creation.
        :param local_provider: Local provider class to instantiate.
        :param local_file: Path to local file for provider initialization.
        :param search_paths: List of paths to search for files.
        :param kwargs: Additional keyword arguments passed to provider creation.
        :raises SPSDKError: When no configuration is provided or provider creation fails.
        :return: Created service provider instance.
        """
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
