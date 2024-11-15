#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Base class for HTTP Clients."""
import abc
import inspect
import json
import logging
import sys
from http import HTTPStatus
from typing import Optional, Type

import requests
from typing_extensions import Self, TypeAlias

from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import get_spsdk_version
from spsdk.utils.schema_validator import CommentedConfig, check_config

logger = logging.getLogger(__name__)

if sys.version_info < (3, 11):
    from enum import Enum

    # This is a simplified backport from Python 3.11 'http' package
    class HTTPMethod(Enum):
        """HTTP methods and descriptions.

        Methods from the following RFCs are all observed:

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
    """HTTP Error raised when processing requests and responses."""

    def __init__(self, status_code: int, response: dict, desc: Optional[str] = None) -> None:
        """Initialize HTTP Client Error object."""
        super().__init__(desc)
        self.status_code = status_code
        self.response = response


class HTTPClientBase(abc.ABC):
    """Base class for creating HTTP clients."""

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
        **kwargs: str,
    ) -> None:
        """Initialize HTTP Client.

        :param host: HTTP Server address, defaults to "localhost"
        :param port: HTTP server port, defaults to 8000
        :param url_prefix: Prefix for API routes, defaults to "api"
        :param timeout: Timeout for API call, defaults to 60
        :param use_ssl: Use SSL (https) connection, defaults to False
        :param raise_exceptions: Raise exception in case response status code is >= 400, defaults to True
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
            "spsdk-version": str(get_spsdk_version()),
            "spsdk-api-version": self.api_version,
            "Connection": "keep-alive",
            "Keep-Alive": "timeout=60, max=100",
        }
        self.raise_exceptions = raise_exceptions
        self.session = requests.Session()

    def __init_subclass__(cls) -> None:
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

        :param url: REST API endpoint URL
        :param data: JSON payload data, defaults to None
        :raises HTTPClientError: HTTP Error during API request if error raising is enabled
        :raises SPSDKError: Invalid response data (not a valid dictionary)
        :return: REST API data response as dictionary and status code
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
    def _check_response(self, response: dict, names_types: list[tuple[str, Type]]) -> None:
        """Check if the response contains required data.

        :param response: Response to check
        :param names_types: Name and type of required response members
        :raises SPSDKError: Response doesn't contain required member
        :raises SPSDKError: Responses' member has incorrect type
        """
        for name, typ in names_types:
            if name not in response:
                raise SPSDKError(f"Response object doesn't contain member '{name}'")
            if not isinstance(response[name], typ):
                raise SPSDKError(
                    f"Response member '{name}' is not a instance of '{typ}' but '{type(response[name])}'"
                )

    @classmethod
    def get_validation_schema(cls) -> dict:
        """Get JSON schema for validating configuration data."""
        raise NotImplementedError()

    @classmethod
    def validate_config(cls, config_data: dict, search_paths: Optional[list[str]] = None) -> None:
        """Validate configuration data using JSON schema specific to this class.

        :param config_data: Configuration data
        :param search_paths: Paths where to look for files referenced in config data, defaults to None
        """
        schema = cls.get_validation_schema()
        check_config(config=config_data, schemas=[schema], search_paths=search_paths)

    @classmethod
    def from_config(cls, config_data: dict, search_paths: Optional[list[str]] = None) -> Self:
        """Create instance of this class based on configuration data.

        __init__ method of this class will be called with data from config_data.

        :param config_data: Configuration data
        :param search_paths: Paths where to look for files referenced in config data, defaults to None
        :return: Instance of this class
        """
        cls.validate_config(config_data=config_data, search_paths=search_paths)
        return cls(**config_data)

    @classmethod
    def generate_config_template(
        cls, schemas: Optional[list[dict]] = None, title: Optional[str] = None
    ) -> str:
        """Generate configuration YAML template."""
        schemas = schemas or [cls.get_validation_schema()]
        yaml_data = CommentedConfig(
            main_title=title or f"{cls.__name__} class configuration template",
            schemas=schemas,
        ).get_template()
        return yaml_data
