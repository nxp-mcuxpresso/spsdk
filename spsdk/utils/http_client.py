#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK HTTP client utilities.

This module provides base classes and error handling for HTTP client
implementations used across SPSDK for secure provisioning operations.
"""

import abc
import inspect
import json
import logging
import sys
from http import HTTPStatus
from typing import Any, Optional, Type, Union

import requests
from typing_extensions import Self, TypeAlias

from spsdk import __version__ as spsdk_version
from spsdk.exceptions import SPSDKError
from spsdk.utils.config import Config
from spsdk.utils.family import FamilyRevision
from spsdk.utils.schema_validator import CommentedConfig

logger = logging.getLogger(__name__)

if sys.version_info < (3, 11):
    from enum import Enum

    # This is a simplified backport from Python 3.11 'http' package
    class HTTPMethod(Enum):
        """HTTP method enumeration for standardized request types.

        This enumeration provides constants for standard HTTP methods as defined
        in RFC specifications, ensuring consistent usage across SPSDK HTTP operations.
        Methods from the following RFCs are supported:
            * RFC 7231: Hypertext Transfer Protocol (HTTP/1.1), obsoletes 2616
            * RFC 5789: PATCH Method for HTTP
        """

        CONNECT = "CONNECT"
        DELETE = "DELETE"
        GET = "GET"
        HEAD = "HEAD"
        OPTIONS = "OPTIONS"
        PATCH = "PATCH"
        POST = "POST"
        PUT = "PUT"
        TRACE = "TRACE"

else:
    from http import HTTPMethod


class SPSDKHTTPClientError(SPSDKError):
    """SPSDK HTTP Client Error exception.

    This exception is raised when HTTP operations fail during communication
    with remote services, providing detailed error information including
    status codes and response data for debugging and error handling.
    """

    def __init__(self, status_code: int, response: dict, desc: Optional[str] = None) -> None:
        """Initialize HTTP Client Error object.

        :param status_code: HTTP status code from the failed request.
        :param response: Response data dictionary from the failed HTTP request.
        :param desc: Optional description of the error, defaults to None.
        """
        super().__init__(desc)
        self.status_code = status_code
        self.response = response


class HTTPClientBase(abc.ABC):
    """SPSDK HTTP Client Base Class.

    Abstract base class for implementing HTTP clients that communicate with SPSDK-compatible
    servers. Provides common functionality for HTTP operations, session management, and
    configuration handling across different HTTP client implementations.

    :cvar Method: Type alias for HTTPMethod enumeration.
    :cvar Status: Type alias for HTTPStatus enumeration.
    """

    api_version: str
    #: Helper alias for HTTP Methods
    Method: TypeAlias = HTTPMethod
    #: Helper alias for HTTP Status
    Status: TypeAlias = HTTPStatus

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8000,
        url_prefix: Optional[str] = "api",
        timeout: int = 60,
        use_ssl: bool = False,
        raise_exceptions: bool = True,
        **kwargs: Union[str, int, bool],
    ) -> None:
        """Initialize HTTP Client.

        Creates a new HTTP client instance for communicating with SPSDK-compatible servers.
        Automatically configures the base URL, headers, and connection parameters.

        :param host: HTTP Server address, defaults to "localhost"
        :param port: HTTP server port, defaults to 8000
        :param url_prefix: Prefix for API routes, defaults to "api"
        :param timeout: Timeout for API call in seconds, defaults to 60
        :param use_ssl: Use SSL (https) connection, defaults to False
        :param raise_exceptions: Raise exception when response status code is >= 400, defaults to True
        :param kwargs: Additional keyword arguments for HTTP client configuration
        """
        super().__init__()
        self.base_url = host
        if use_ssl and not host.startswith("https"):
            if not host.startswith("https"):
                self.base_url = f"https://{host}:{port}"
        else:
            if not host.startswith("http"):
                self.base_url = f"http://{host}:{port}"
        self.base_url += f"/{url_prefix}" if url_prefix else ""
        self.kwargs = kwargs
        self.timeout = timeout
        self.headers = {
            "spsdk-version": spsdk_version,
            "spsdk-api-version": self.api_version,
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=60, max=100",
        }
        self.raise_exceptions = raise_exceptions
        self.session = requests.Session()

    def __init_subclass__(cls) -> None:
        """Initialize subclass with API version validation.

        Validates that non-abstract subclasses have the required 'api_version' attribute set.
        This ensures all concrete HTTP client implementations specify their API version.

        :param cls: The subclass being initialized.
        :raises SPSDKError: If the subclass is not abstract and lacks 'api_version' attribute.
        """
        if not inspect.isabstract(cls) and not hasattr(cls, "api_version"):
            raise SPSDKError(f"{cls.__name__}.api_version is not set")
        return super().__init_subclass__()

    def _handle_request(
        self,
        method: Method,
        url: str,
        param_data: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> requests.Response:
        """Handle REST API request.

        The method constructs the full URL, prepares request parameters and JSON payload,
        sends the HTTP request using the specified method, and logs the request/response details.

        :param method: HTTP method to use for the request.
        :param url: REST API endpoint URL (must start with '/').
        :param param_data: URL parameters for the request, defaults to None.
        :param json_data: JSON payload data for request body, defaults to None.
        :raises SPSDKError: URL does not start with '/'.
        :return: HTTP response object from the API request.
        """
        if not url.startswith("/"):
            raise SPSDKError("URL shall start with '/'")
        params = param_data or {}
        json_payload = json_data or {}
        json_payload.update(self.kwargs)
        full_url = self.base_url + url
        logger.info(f"Requesting: {full_url}")
        logger.debug(f"Request params: {json.dumps(params, indent=2)}")
        logger.debug(f"Request body: {json.dumps(json_payload, indent=2)}")

        response = self.session.request(
            method=method.value,
            url=full_url,
            json=json_payload,
            params=params,
            headers=self.headers,
            timeout=self.timeout,
        )
        logger.info(f"Response: {response}")
        if logger.isEnabledFor(logging.DEBUG):
            try:
                body = response.json()
                logger.debug(f"Body: {json.dumps(body, indent=2)}")
            except json.JSONDecodeError:
                logger.debug("No JSON body found in the response")

        return response

    # pylint: disable=no-self-use  # derived classes may use self object
    def _check_response(
        self, response: requests.Response, names_types: list[tuple[str, Type]]
    ) -> dict:
        """Check if the response contains required data.

        Validates HTTP response status and verifies that the JSON response contains all required
        members with correct types.

        :param response: HTTP response object to validate.
        :param names_types: List of tuples containing name and expected type of required response
            members.
        :raises SPSDKError: Response doesn't contain required member.
        :raises SPSDKError: Response member has incorrect type.
        :return: Validated JSON response data as dictionary.
        """
        response.raise_for_status()
        response_data = response.json()
        for name, typ in names_types:
            if name not in response_data:
                raise SPSDKError(f"Response object doesn't contain member '{name}'")
            if not isinstance(response_data[name], typ):
                raise SPSDKError(
                    f"Response member '{name}' is not a instance of '{typ}' but '{type(response_data[name])}'"
                )
        return response_data

    @classmethod
    def get_validation_schemas(cls, family: FamilyRevision) -> list[dict[str, Any]]:
        """Get JSON schema for validating configuration data.

        :param family: Family revision to get validation schemas for.
        :raises NotImplementedError: Method must be implemented by subclasses.
        :return: List of JSON schema dictionaries for configuration validation.
        """
        raise NotImplementedError()

    @classmethod
    def validate_config(cls, config: Config) -> None:
        """Validate configuration data using JSON schema specific to this class.

        The method retrieves validation schemas for the family revision specified in the
        configuration and performs comprehensive validation including unknown properties check.

        :param config: Configuration data to be validated.
        :raises SPSDKError: Invalid configuration data or schema validation failure.
        """
        schemas = cls.get_validation_schemas(FamilyRevision.load_from_config(config))
        config.check(schemas, check_unknown_props=True)

    @classmethod
    def load_from_config(cls, config: Config) -> Self:
        """Create instance of this class based on configuration data.

        The method validates the provided configuration and initializes a new instance
        using the configuration parameters as keyword arguments to the constructor.

        :param config: Configuration data containing initialization parameters.
        :return: Instance of this class initialized with the provided configuration.
        """
        cls.validate_config(config)
        return cls(**config)

    @classmethod
    def get_config_template(
        cls,
        family: FamilyRevision,
        schemas: Optional[list[dict]] = None,
        title: Optional[str] = None,
    ) -> str:
        """Generate configuration YAML template.

        Creates a YAML configuration template for the class using provided or default validation schemas.
        The template includes commented configuration options based on the schemas.

        :param family: Target family and revision for configuration template.
        :param schemas: Optional list of validation schemas to use for template generation.
        :param title: Optional custom title for the configuration template.
        :return: YAML configuration template as string.
        """
        schemas = schemas or cls.get_validation_schemas(family)
        yaml_data = CommentedConfig(
            main_title=title or f"{cls.__name__} class configuration template",
            schemas=schemas,
        ).get_template()
        return yaml_data
